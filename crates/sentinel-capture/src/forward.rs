//! Shipping observations from a capture service to the engine.
//!
//! Capture is to run as its own service, apart from the engine; this is the
//! capture side of that link: it takes the observations a backend produces
//! and writes them to the engine's ingest listener as newline-delimited JSON
//! (see [`sentinel_core::ingest`]).
//!
//! The engine must be able to go away - stopped, restarted, crashed - without
//! the capture service noticing anything worse than a dropped connection:
//!
//! * **It reconnects** with exponential backoff (1 s up to 30 s), and says so
//!   once per outage rather than once per attempt.
//! * **It buffers, boundedly.** While the engine is unreachable observations
//!   queue up to a fixed limit; past that the *oldest* is dropped, since the
//!   newest is what says who is here now. Every drop is counted and reported
//!   to the engine in [`CaptureStats::dropped`] once it is back, so the loss
//!   can be shown rather than hidden.
//!
//! Observations already written into the socket when the engine dies are lost
//! with the connection and are not counted - TCP does not say how much of its
//! buffer the far end read. That is at most the write buffer and a socket
//! buffer's worth.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sentinel_core::ingest::{CaptureSource, CaptureStats, IngestMessage};
use sentinel_core::observation::Observation;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};
use tracing::{info, warn};

/// Default queue length: at an assumed few tens of sightings a second,
/// several minutes without the engine.
pub const DEFAULT_QUEUE: usize = 20_000;
const STATS_EVERY: Duration = Duration::from_secs(2);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// What the forwarder itself has done, beside the radio's own counters.
#[derive(Debug, Default)]
pub struct ForwardStats {
    pub sent: AtomicU64,
    pub dropped: AtomicU64,
    pub connected: AtomicBool,
}

struct Queue {
    items: Mutex<VecDeque<Observation>>,
    capacity: usize,
    ready: Notify,
}

/// Forward everything `rx` yields to the engine at `engine` (`host:port`).
/// `radio_stats` is polled for the counters sent alongside.
///
/// It returns once `rx` has closed and no connection is open. While connected
/// it keeps sending stats even after `rx` closes, so a caller that wants it
/// gone sooner aborts the task.
pub async fn forward(
    source: CaptureSource,
    engine: String,
    mut rx: mpsc::Receiver<Observation>,
    radio_stats: Arc<dyn Fn() -> CaptureStats + Send + Sync>,
    stats: Arc<ForwardStats>,
    capacity: usize,
) {
    let queue = Arc::new(Queue {
        items: Mutex::new(VecDeque::new()),
        capacity: capacity.max(1),
        ready: Notify::new(),
    });

    // Drain the backend continuously, connected or not, so the backend's
    // channel does not fill, and loss happens here in the queue, where it is
    // counted, rather than at the backend, where it is not.
    let drain = {
        let (queue, stats) = (queue.clone(), stats.clone());
        tokio::spawn(async move {
            while let Some(obs) = rx.recv().await {
                {
                    let mut q = queue.items.lock().unwrap_or_else(|e| e.into_inner());
                    if q.len() >= queue.capacity {
                        q.pop_front();
                        stats.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    q.push_back(obs);
                }
                queue.ready.notify_one();
            }
        })
    };

    let mut backoff = Duration::from_secs(1);
    let mut outage_reported = false;
    while !drain.is_finished() {
        match TcpStream::connect(&engine).await {
            Ok(sock) => {
                let _ = sock.set_nodelay(true);
                info!(%source, %engine, "connected to the engine");
                stats.connected.store(true, Ordering::Relaxed);
                backoff = Duration::from_secs(1);
                outage_reported = false;
                let result = session(sock, source, &queue, &radio_stats, &stats).await;
                stats.connected.store(false, Ordering::Relaxed);
                if let Err(e) = result {
                    warn!(%source, "lost the connection to the engine: {e}; reconnecting");
                }
            }
            Err(e) => {
                if !outage_reported {
                    warn!(
                        %source, %engine,
                        "cannot reach the engine ({e}); queueing up to {} observations and retrying",
                        queue.capacity
                    );
                    outage_reported = true;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

async fn session(
    sock: TcpStream,
    source: CaptureSource,
    queue: &Queue,
    radio_stats: &Arc<dyn Fn() -> CaptureStats + Send + Sync>,
    stats: &ForwardStats,
) -> std::io::Result<()> {
    let mut w = BufWriter::new(sock);
    w.write_all(IngestMessage::Hello { source }.to_line().as_bytes())
        .await?;
    let report = |w_stats: &ForwardStats| {
        let mut s = radio_stats();
        s.dropped = w_stats.dropped.load(Ordering::Relaxed);
        IngestMessage::Stats { stats: s }.to_line()
    };
    w.write_all(report(stats).as_bytes()).await?;
    w.flush().await?;

    let mut tick = tokio::time::interval(STATS_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let batch: Vec<Observation> = {
            let mut q = queue.items.lock().unwrap_or_else(|e| e.into_inner());
            q.drain(..).collect()
        };
        let mut sent = 0usize;
        let mut failed = None;
        for obs in &batch {
            let line = IngestMessage::Observation { obs: obs.clone() }.to_line();
            if let Err(e) = w.write_all(line.as_bytes()).await {
                failed = Some(e);
                break;
            }
            sent += 1;
        }
        if failed.is_none() {
            if let Err(e) = w.flush().await {
                failed = Some(e);
            }
        }
        if let Some(e) = failed {
            // Put back what never left, ahead of anything newer, so a
            // reconnect resends it in order.
            let mut q = queue.items.lock().unwrap_or_else(|e| e.into_inner());
            for obs in batch.into_iter().skip(sent).rev() {
                q.push_front(obs);
            }
            while q.len() > queue.capacity {
                q.pop_front();
                stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
            return Err(e);
        }
        stats.sent.fetch_add(sent as u64, Ordering::Relaxed);

        tokio::select! {
            _ = queue.ready.notified() => {}
            _ = tick.tick() => {
                w.write_all(report(stats).as_bytes()).await?;
                w.flush().await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinel_core::fingerprint::{BleEvidence, Evidence};
    use sentinel_core::mac::MacKind;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpListener;

    fn obs(n: u8) -> Observation {
        Observation {
            ts: Utc::now(),
            mac: format!("40:00:00:00:00:{n:02x}").parse().unwrap(),
            mac_kind: MacKind::BleStaticRandom,
            rssi: Some(-50),
            evidence: Evidence::Ble(BleEvidence::default()),
        }
    }

    async fn next(lines: &mut tokio::io::Lines<BufReader<TcpStream>>) -> IngestMessage {
        let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .expect("timed out waiting for a line")
            .unwrap()
            .expect("connection closed");
        IngestMessage::from_line(&line).unwrap()
    }

    /// The engine is down when capture starts. Observations queue, the oldest
    /// beyond the limit are dropped and **counted**, and when the engine comes
    /// up it receives a hello, a stats line reporting the loss, and the
    /// surviving observations - newest kept, in order.
    #[tokio::test]
    async fn queues_while_the_engine_is_down_drops_the_oldest_and_reports_it() {
        // Reserve a port, then free it so the first connects are refused.
        let addr = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let (tx, rx) = mpsc::channel(64);
        let stats = Arc::new(ForwardStats::default());
        let task = tokio::spawn(forward(
            CaptureSource::Ble,
            addr.to_string(),
            rx,
            Arc::new(CaptureStats::default),
            stats.clone(),
            3,
        ));

        for n in 0..5 {
            tx.send(obs(n)).await.unwrap();
        }
        // Let the drain task take all five.
        for _ in 0..100 {
            if stats.dropped.load(Ordering::Relaxed) == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(stats.dropped.load(Ordering::Relaxed), 2, "capacity 3, five sent");

        let listener = TcpListener::bind(addr).await.unwrap();
        let (sock, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("the forwarder never reconnected")
            .unwrap();
        let mut lines = BufReader::new(sock).lines();

        assert!(matches!(next(&mut lines).await, IngestMessage::Hello { source: CaptureSource::Ble }));
        match next(&mut lines).await {
            IngestMessage::Stats { stats } => assert_eq!(stats.dropped, 2, "the loss is reported"),
            other => panic!("expected stats, got {other:?}"),
        }
        for n in 2..5 {
            match next(&mut lines).await {
                IngestMessage::Observation { obs } => assert_eq!(obs.mac, self::obs(n).mac),
                other => panic!("expected observation {n}, got {other:?}"),
            }
        }
        drop(tx);
        task.abort();
    }

    /// The engine restarting must not need the capture service restarted too.
    #[tokio::test]
    async fn reconnects_after_the_engine_goes_away() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel(64);
        let stats = Arc::new(ForwardStats::default());
        let task = tokio::spawn(forward(
            CaptureSource::Wifi,
            addr.to_string(),
            rx,
            Arc::new(CaptureStats::default),
            stats.clone(),
            DEFAULT_QUEUE,
        ));

        // First engine: accept, read the hello, then die.
        let (sock, _) = listener.accept().await.unwrap();
        let mut lines = BufReader::new(sock).lines();
        assert!(matches!(next(&mut lines).await, IngestMessage::Hello { .. }));
        drop(lines);

        // Keep sending; the writes fail, the forwarder reconnects.
        let feeder = tokio::spawn(async move {
            for n in 0..=255u8 {
                if tx.send(obs(n)).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        let (sock, _) = tokio::time::timeout(Duration::from_secs(15), listener.accept())
            .await
            .expect("no reconnect after the engine went away")
            .unwrap();
        let mut lines = BufReader::new(sock).lines();
        assert!(matches!(next(&mut lines).await, IngestMessage::Hello { source: CaptureSource::Wifi }));
        feeder.abort();
        task.abort();
    }
}
