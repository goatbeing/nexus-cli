//! Pipelined authenticated worker with overlapped fetch/prove/submit stages
//!
//! This worker improves throughput by running fetch, prove, and submit stages
//! concurrently rather than sequentially. While proving task N, it can fetch
//! task N+1, eliminating idle time and maximizing hardware utilization.

use super::core::{EventSender, WorkerConfig};
use super::fetcher::TaskFetcher;
use super::prover::TaskProver;
use super::submitter::ProofSubmitter;
use crate::events::{Event, ProverState};
use crate::orchestrator::OrchestratorClient;
use crate::prover::ProverResult;
use crate::task::Task;

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;

/// Pipelined worker that overlaps fetch, prove, and submit stages for maximum throughput
pub struct PipelinedWorker {
    fetcher: TaskFetcher,
    prover: TaskProver,
    submitter: ProofSubmitter,
    event_sender: EventSender,
    max_tasks: Option<u32>,
    shutdown_sender: broadcast::Sender<()>,
}

impl PipelinedWorker {
    pub fn new(
        node_id: u64,
        signing_key: SigningKey,
        orchestrator: OrchestratorClient,
        config: WorkerConfig,
        event_sender: mpsc::Sender<Event>,
        max_tasks: Option<u32>,
        shutdown_sender: broadcast::Sender<()>,
    ) -> Self {
        let event_sender_helper = EventSender::new(event_sender);

        // Create the 3 specialized components
        let fetcher = TaskFetcher::new(
            node_id,
            signing_key.verifying_key(),
            Box::new(orchestrator.clone()),
            event_sender_helper.clone(),
            &config,
        );

        let prover = TaskProver::new(event_sender_helper.clone(), config.clone());

        let submitter = ProofSubmitter::new(
            signing_key,
            Box::new(orchestrator),
            event_sender_helper.clone(),
            &config,
        );

        Self {
            fetcher,
            prover,
            submitter,
            event_sender: event_sender_helper,
            max_tasks,
            shutdown_sender,
        }
    }

    /// Start the pipelined worker with overlapped stages
    pub async fn run(mut self, shutdown: broadcast::Receiver<()>) -> Vec<JoinHandle<()>> {
        let mut join_handles = Vec::new();

        // Create channels for pipeline stages
        // Buffer size of 2 allows one task to be proving while next is fetched
        let (task_tx, mut task_rx) = mpsc::channel::<Task>(2);
        let (proof_tx, mut proof_rx) = mpsc::channel::<(Task, ProverResult)>(2);

        // Shared state for tracking completed tasks and timing
        let tasks_completed = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let tasks_completed_submitter = tasks_completed.clone();
        
        // Channel to communicate timing data and task info from prover to submitter
        let (timing_tx, mut timing_rx) = mpsc::channel::<(u64, usize)>(10); // (duration_secs, task_size)

        // Wrap fetcher in Arc<Mutex<>> for shared access between stages
        let fetcher = Arc::new(Mutex::new(self.fetcher));
        let fetcher_for_fetch = fetcher.clone();
        let fetcher_for_submit = fetcher.clone();

        let shutdown_sender_clone = self.shutdown_sender.clone();

        // Send initial state (match original exactly)
        self.event_sender
            .send_event(Event::state_change(
                ProverState::Waiting,
                "Ready to fetch tasks".to_string(),
            ))
            .await;

        // Stage 1: Task Fetcher (runs independently, respects rate limits)
        let mut shutdown_fetcher = self.shutdown_sender.subscribe();
        let fetcher_handle = tokio::spawn(async move {
            'fetch_loop: loop {
                // Check for shutdown first
                if shutdown_fetcher.try_recv().is_ok() {
                    drop(task_tx); // Close channel to signal downstream
                    break;
                }

                // Fetch task with lock
                let mut fetcher_guard = fetcher_for_fetch.lock().await;
                let result = fetcher_guard.fetch_task().await;
                drop(fetcher_guard); // Release lock immediately
                
                match result {
                    Ok(task) => {
                        // Try to send task to prover stage
                        if task_tx.send(task).await.is_err() {
                            // Channel closed, shutdown requested
                            break 'fetch_loop;
                        }
                    }
                    Err(_) => {
                        // Error already logged in fetcher, wait before retry
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
        join_handles.push(fetcher_handle);

        // Stage 2: Prover (receives tasks, generates proofs in parallel)
        let mut shutdown_prover = self.shutdown_sender.subscribe();
        let prover = self.prover.clone();
        let event_sender_prover = self.event_sender.clone();
        let prover_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_prover.recv() => {
                        drop(proof_tx); // Close channel to signal downstream
                        break;
                    }
                    task_opt = task_rx.recv() => {
                        match task_opt {
                            Some(task) => {
                                // Track start time for difficulty adjustment
                                let start_time = std::time::Instant::now();

                                // Send state change to Proving
                                event_sender_prover
                                    .send_event(Event::state_change(
                                        ProverState::Proving,
                                        format!("Step 2 of 4: Proving task {}", task.task_id),
                                    ))
                                    .await;

                                match prover.prove_task(&task).await {
                                    Ok(proof_result) => {
                                        // Calculate duration for this task
                                        let duration = start_time.elapsed();
                                        let duration_secs = duration.as_secs();
                                        let task_size = task.public_inputs_list.len();

                                        // Send to submit stage
                                        if proof_tx.send((task.clone(), proof_result)).await.is_err() {
                                            break; // Channel closed
                                        }

                                        // Send timing data and task size for difficulty adjustment and logging
                                        let _ = timing_tx.send((duration_secs, task_size)).await;
                                    }
                                    Err(_) => {
                                        // Error already logged, continue to next task
                                        event_sender_prover
                                            .send_event(Event::state_change(
                                                ProverState::Waiting,
                                                "Proof generation failed, ready for next task".to_string(),
                                            ))
                                            .await;
                                    }
                                }
                            }
                            None => {
                                // Channel closed, fetcher shut down
                                drop(proof_tx);
                                break;
                            }
                        }
                    }
                }
            }
        });
        join_handles.push(prover_handle);

        // Stage 3: Submitter (receives proofs, submits with retry)
        let mut shutdown_submitter = shutdown;
        let submitter_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_submitter.recv() => break,
                    proof_opt = proof_rx.recv() => {
                        match proof_opt {
                            Some((task, proof_result)) => {
                                let submission_result = self.submitter.submit_proof(&task, &proof_result).await;

                                if submission_result.is_ok() {
                                    let completed = tasks_completed_submitter.fetch_add(
                                        1,
                                        std::sync::atomic::Ordering::SeqCst
                                    ) + 1;

                                    // Try to get timing data and task size
                                    let (duration_secs, task_size) = match timing_rx.try_recv() {
                                        Ok((secs, size)) => (secs, size),
                                        Err(_) => (60, task.public_inputs_list.len()), // Conservative fallback
                                    };
                                    
                                    // Update difficulty tracking with actual timing and get difficulty
                                    let mut fetcher_guard = fetcher_for_submit.lock().await;
                                    fetcher_guard.update_success_tracking(duration_secs);
                                    let difficulty = fetcher_guard
                                        .last_success_difficulty
                                        .map(|d| d.as_str_name())
                                        .unwrap_or("Unknown");
                                    drop(fetcher_guard);

                                    // Format message like original: "task_id completed, Task size: X, Duration: Xs, Difficulty: Y"
                                    self.event_sender
                                        .send_event(Event::state_change(
                                            ProverState::Waiting,
                                            format!(
                                                "{} completed, Task size: {}, Duration: {}s, Difficulty: {}",
                                                task.task_id,
                                                task_size,
                                                duration_secs,
                                                difficulty
                                            ),
                                        ))
                                        .await;

                                    // Check max tasks limit
                                    if let Some(max) = self.max_tasks {
                                        if completed >= max {
                                            tokio::time::sleep(Duration::from_millis(100)).await;
                                            self.event_sender
                                                .send_event(Event::state_change(
                                                    ProverState::Waiting,
                                                    format!("Completed {} tasks, shutting down", completed),
                                                ))
                                                .await;
                                            let _ = shutdown_sender_clone.send(());
                                            break;
                                        }
                                    }

                                    // Send "ready for next task" message (match original behavior)
                                    self.event_sender
                                        .send_event(Event::state_change(
                                            ProverState::Waiting,
                                            "Task completed, ready for next task".to_string(),
                                        ))
                                        .await;
                                }
                            }
                            None => {
                                // Channel closed, prover shut down
                                break;
                            }
                        }
                    }
                }
            }
        });
        join_handles.push(submitter_handle);

        join_handles
    }
}

