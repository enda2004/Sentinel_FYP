//! Live 802.11 capture from a monitor-mode interface.
//!
//! libpcap does the reading; a companion thread retunes the adapter so the
//! single radio can cover several channels. Hopping is a real trade-off: with
//! one adapter, time spent on channel 36 is time not spent on channel 6, so
//! with N channels each one is heard about 1/N of the time a dedicated radio
//! would hear it. Probe requests are retransmitted across channels, which is
//! what makes the compromise workable at all.

use std::collections::HashSet;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration as StdDuration;

use anyhow::{Context, Result};
use chrono::Utc;
use sentinel_core::config::WifiConfig;
use sentinel_core::mac::{MacAddr, MacKind};
use sentinel_core::observation::Observation;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use crate::{dot11, radiotap};

/// Consecutive failed reads after which the adapter is taken to be gone: 25,
/// 200 ms apart, is five seconds.
const MAX_READ_ERRORS: u32 = 25;

#[derive(Debug, Default)]
pub struct WifiStats {
    pub frames: AtomicU64,
    pub parsed: AtomicU64,
    pub bad_fcs: AtomicU64,
    pub too_weak: AtomicU64,
    /// Frames discarded because they came from this host's own radios.
    pub self_frames: AtomicU64,
    pub current_channel: AtomicU64,
}

/// Start capturing. Blocks until `shutdown` is set, so call it on a dedicated
/// thread.
pub fn run(
    cfg: WifiConfig,
    tx: Sender<Observation>,
    shutdown: Arc<AtomicBool>,
    stats: Arc<WifiStats>,
) -> Result<()> {
    let mut cap = pcap::Capture::from_device(cfg.interface.as_str())
        .with_context(|| format!("opening interface {}", cfg.interface))?
        .promisc(true)
        .immediate_mode(true)
        .snaplen(2048)
        .buffer_size(cfg.buffer_bytes)
        .timeout(200)
        .open()
        .with_context(|| {
            format!(
                "activating capture on {} - is it in monitor mode, and running as root?",
                cfg.interface
            )
        })?;

    let linktype = cap.get_datalink();
    let has_radiotap = linktype == pcap::Linktype::IEEE802_11_RADIOTAP;
    if !has_radiotap && linktype != pcap::Linktype::IEEE802_11 {
        anyhow::bail!(
            "{} has link type {:?}; expected IEEE802_11_RADIOTAP. \
             The interface is probably not in monitor mode - see scripts/monitor-mode.sh",
            cfg.interface,
            linktype
        );
    }
    if !has_radiotap {
        warn!("no radiotap header on this interface: RSSI and channel will be unavailable");
    }

    // Management frames plus data frames when client tracking is on. Filtering
    // in the kernel keeps a busy 5 GHz channel from swamping userspace.
    let filter = if cfg.capture_data_frames {
        "type mgt or type data"
    } else {
        "type mgt"
    };
    if let Err(e) = cap.filter(filter, true) {
        warn!("could not install BPF filter ({e}); capturing everything instead");
    }

    // libpcap's read timeout is not a guaranteed wakeup: on a channel with no
    // traffic, `next_packet` can block until a frame eventually arrives, so a
    // shutdown request could wait indefinitely. Non-blocking reads, with the
    // loop waiting on the descriptor itself, put a hard bound on how long it
    // can sit between shutdown checks.
    let fd = cap.as_raw_fd();
    let mut cap = cap
        .setnonblock()
        .context("switching the capture to non-blocking mode")?;

    // Stops the hopper on its own, independently of the shared shutdown flag.
    let hop_stop = Arc::new(AtomicBool::new(false));
    let hopper = if cfg.hop {
        Some(spawn_hopper(
            cfg.clone(),
            shutdown.clone(),
            hop_stop.clone(),
            stats.clone(),
        ))
    } else {
        None
    };

    let local = local_addresses();
    info!(
        interface = %cfg.interface,
        channels = ?cfg.channels,
        ignoring_own_addresses = local.len(),
        "802.11 capture running"
    );

    let mut read_errors = 0u32;
    while !shutdown.load(Ordering::Relaxed) {
        if !wait_readable(fd, 200) {
            continue;
        }
        // Drain everything buffered before going back to the poll, so a busy
        // channel is not rate-limited to one frame per wakeup.
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    read_errors = 0;
                    stats.frames.fetch_add(1, Ordering::Relaxed);
                    if let Some(obs) = decode(packet.data, has_radiotap, &cfg, &stats, &local) {
                        stats.parsed.fetch_add(1, Ordering::Relaxed);
                        // Never wait for room: a stalled reader would lose
                        // frames in the kernel instead. When the channel is
                        // full, this new sighting is the one dropped.
                        match tx.try_send(obs) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                debug!("observation channel full; dropping a Wi-Fi sighting")
                            }
                            Err(TrySendError::Closed(_)) => {
                                return finish(&hop_stop, hopper, "observation receiver closed")
                            }
                        }
                    }
                }
                // Non-blocking: nothing left in the buffer right now.
                Err(pcap::Error::TimeoutExpired) => {
                    read_errors = 0;
                    break;
                }
                Err(pcap::Error::NoMorePackets) => {
                    return finish(&hop_stop, hopper, "no more packets")
                }
                Err(e) => {
                    read_errors += 1;
                    if read_errors >= MAX_READ_ERRORS {
                        finish(&hop_stop, hopper, "the adapter keeps failing")?;
                        return Err(e).with_context(|| format!("reading from {}", cfg.interface));
                    }
                    warn!("pcap read error: {e}");
                    thread::sleep(StdDuration::from_millis(200));
                    break;
                }
            }
        }
    }

    finish(&hop_stop, hopper, "shutdown requested")
}

fn finish(
    hop_stop: &Arc<AtomicBool>,
    hopper: Option<thread::JoinHandle<()>>,
    reason: &str,
) -> Result<()> {
    // The hopper loops until it is told to stop. When capture ends by itself
    // (the adapter fails, or nothing receives observations any more) the
    // shared `shutdown` flag is still clear, so the hopper has a flag of its
    // own. Only that one is set: `shutdown` may be shared with other capture,
    // which must keep running when Wi-Fi stops.
    hop_stop.store(true, Ordering::Relaxed);
    if let Some(h) = hopper {
        let _ = h.join();
    }
    info!(reason, "802.11 capture stopped");
    Ok(())
}

/// Block until `fd` has data or `timeout_ms` elapses. Returns true if readable,
/// or if the descriptor reports an error or hang-up: the next read then
/// surfaces the error, instead of the loop polling again at once, forever.
fn wait_readable(fd: std::os::unix::io::RawFd, timeout_ms: libc::c_int) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: polling a single valid descriptor owned by the live capture.
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    rc > 0 && pfd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
}

/// Hardware addresses belonging to this host.
///
/// A monitor interface hears the machine it is plugged into. Its other radio
/// (on a Raspberry Pi, `wlan0`, joined to the home network) transmits a few
/// centimetres from the capture antenna, so without this the host would be
/// recorded as a permanently present client at very strong signal: it passes
/// any signal floor and is not infrastructure, so nothing else filters it.
fn local_addresses() -> HashSet<MacAddr> {
    let mut set = HashSet::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        warn!("cannot enumerate local interfaces; this host may log itself as a device");
        return set;
    };
    for entry in entries.flatten() {
        let path = entry.path().join("address");
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(mac) = text.trim().parse::<MacAddr>() {
                if !mac.is_zero() {
                    set.insert(mac);
                }
            }
        }
    }
    set
}

/// Turn one captured frame into an [`Observation`].
fn decode(
    data: &[u8],
    has_radiotap: bool,
    cfg: &WifiConfig,
    stats: &WifiStats,
    local: &HashSet<MacAddr>,
) -> Option<Observation> {
    let (body, rssi, channel) = if has_radiotap {
        let rt = radiotap::parse(data)?;
        if rt.bad_fcs {
            stats.bad_fcs.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        (rt.frame(data)?, rt.signal_dbm, rt.channel())
    } else {
        (data, None, None)
    };

    if let Some(r) = rssi {
        if r < cfg.min_rssi {
            stats.too_weak.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    }

    let frame = dot11::parse(body, channel, cfg.capture_data_frames)?;
    let mac = frame.transmitter;
    if mac.is_multicast() || mac.is_zero() || mac.is_broadcast() {
        return None;
    }
    // Never fingerprint the machine doing the fingerprinting.
    if local.contains(&mac) {
        stats.self_frames.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    Some(Observation {
        ts: Utc::now(),
        mac,
        mac_kind: MacKind::classify_wifi(&mac),
        rssi,
        evidence: frame.into_evidence(),
    })
}

/// Retune the adapter on a fixed dwell.
fn spawn_hopper(
    cfg: WifiConfig,
    shutdown: Arc<AtomicBool>,
    hop_stop: Arc<AtomicBool>,
    stats: Arc<WifiStats>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let stop = || shutdown.load(Ordering::Relaxed) || hop_stop.load(Ordering::Relaxed);
        let mut idx = 0usize;
        let mut failures = 0u32;
        while !stop() {
            let channel = cfg.channels[idx % cfg.channels.len()];
            match set_channel(&cfg.interface, channel) {
                Ok(()) => {
                    failures = 0;
                    stats.current_channel.store(channel as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    failures += 1;
                    // A channel the regulatory domain forbids will fail every
                    // time; complaining once per pass is enough.
                    if failures <= cfg.channels.len() as u32 {
                        warn!("could not set channel {channel}: {e}");
                    }
                }
            }
            idx += 1;
            // Sleep in slices so shutdown is not delayed by a long dwell.
            let mut remaining = cfg.dwell_ms;
            while remaining > 0 && !stop() {
                let slice = remaining.min(100);
                thread::sleep(StdDuration::from_millis(slice));
                remaining -= slice;
            }
        }
    })
}

fn set_channel(interface: &str, channel: u16) -> Result<()> {
    let out = Command::new("iw")
        .args(["dev", interface, "set", "channel", &channel.to_string()])
        .output()
        .context("running `iw` - is iw installed?")?;
    if !out.status.success() {
        // `iw` can fail with nothing on stderr, for example while the device is
        // being torn down. Fall back to the exit status so the log never shows
        // an empty reason.
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if stderr.is_empty() {
            anyhow::bail!("iw exited with {}", out.status);
        }
        anyhow::bail!("{stderr}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::fingerprint::{Evidence, WifiFrame};

    fn none() -> HashSet<MacAddr> {
        HashSet::new()
    }

    /// A complete radiotap + probe-request frame, as it would come off the wire.
    fn frame(rssi: i8) -> Vec<u8> {
        let present: u32 = (1 << 1) | (1 << 3) | (1 << 5); // flags, channel, signal
        let mut rt = vec![0u8, 0u8, 0, 0];
        rt.extend_from_slice(&present.to_le_bytes());
        rt.push(0x00); // flags @ 8
        rt.push(0x00); // padding: the channel field is 2-byte aligned
        rt.extend_from_slice(&2437u16.to_le_bytes()); // freq @ 10
        rt.extend_from_slice(&0u16.to_le_bytes()); // channel flags
        rt.push(rssi as u8); // signal @ 14
        let len = rt.len() as u16;
        rt[2..4].copy_from_slice(&len.to_le_bytes());

        let mut f = vec![0x40, 0x00, 0, 0]; // probe request, no flags
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0xb2, 1, 2, 3, 4, 5]);
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x00, 0x00]);
        f.extend_from_slice(&[0, 7]); // SSID element
        f.extend_from_slice(b"HomeNet");
        f.extend_from_slice(&[1, 4, 0x02, 0x04, 0x0b, 0x16]);

        rt.extend_from_slice(&f);
        rt
    }

    #[test]
    fn decodes_a_full_frame() {
        let cfg = WifiConfig::default();
        let stats = WifiStats::default();
        let obs = decode(&frame(-45), true, &cfg, &stats, &none()).unwrap();
        assert_eq!(obs.rssi, Some(-45));
        assert_eq!(obs.mac.to_string(), "b2:01:02:03:04:05");
        assert_eq!(obs.mac_kind, MacKind::RandomWifi);
        match obs.evidence {
            Evidence::Wifi(w) => {
                assert_eq!(w.frame, WifiFrame::ProbeRequest);
                assert_eq!(w.channel, Some(6));
                assert_eq!(w.directed_ssids, vec!["HomeNet".to_string()]);
            }
            _ => panic!("expected Wi-Fi evidence"),
        }
    }

    #[test]
    fn drops_frames_below_the_rssi_floor() {
        let cfg = WifiConfig {
            min_rssi: -60,
            ..Default::default()
        };
        let stats = WifiStats::default();
        assert!(decode(&frame(-45), true, &cfg, &stats, &none()).is_some());
        assert!(decode(&frame(-90), true, &cfg, &stats, &none()).is_none());
        assert_eq!(stats.too_weak.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn drops_frames_that_failed_their_checksum() {
        let cfg = WifiConfig::default();
        let stats = WifiStats::default();
        let mut f = frame(-45);
        f[8] = 0x40; // bad-FCS flag
        assert!(decode(&f, true, &cfg, &stats, &none()).is_none());
        assert_eq!(stats.bad_fcs.load(Ordering::Relaxed), 1);
    }

    /// The capture antenna is centimetres from this host's own radios, so it
    /// hears them louder than anything else. This host must never be recorded
    /// as a device.
    #[test]
    fn this_host_is_never_logged_as_a_device() {
        let cfg = WifiConfig::default();
        let stats = WifiStats::default();
        let frame = frame(-45);

        // The transmitter in the test frame is b2:01:02:03:04:05.
        let obs = decode(&frame, true, &cfg, &stats, &none()).unwrap();
        assert_eq!(obs.mac.to_string(), "b2:01:02:03:04:05");

        let mine: HashSet<MacAddr> = ["b2:01:02:03:04:05".parse().unwrap()].into();
        assert!(
            decode(&frame, true, &cfg, &stats, &mine).is_none(),
            "a frame from one of this host's own interfaces must be dropped"
        );
        assert_eq!(stats.self_frames.load(Ordering::Relaxed), 1);

        // An unrelated local address must not suppress anything else.
        let other: HashSet<MacAddr> = ["aa:bb:cc:dd:ee:ff".parse().unwrap()].into();
        assert!(decode(&frame, true, &cfg, &stats, &other).is_some());
    }

    /// Whatever `/sys/class/net` holds, this host's real addresses must be in
    /// the ignore set, and the all-zero placeholder must not be.
    ///
    /// Everything here is a read-only `sysfs` read. No interface is opened,
    /// configured or touched.
    #[test]
    fn local_addresses_are_discovered_from_the_running_system() {
        let local = local_addresses();
        assert!(
            !local.iter().any(|m| m.is_zero()),
            "the all-zero address of a down interface must not be treated as ours"
        );

        let entries = std::fs::read_dir("/sys/class/net")
            .expect("every Linux host exposes /sys/class/net");

        let mut real_addresses = 0usize;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(text) = std::fs::read_to_string(entry.path().join("address")) else {
                continue;
            };
            let Ok(mac) = text.trim().parse::<MacAddr>() else {
                continue;
            };

            if mac.is_zero() {
                // `lo` reports 00:00:00:00:00:00, which is not an address of
                // this host, so it has no place in the ignore set.
                assert!(
                    !local.contains(&mac),
                    "{name} has no address and must not be in the ignore set"
                );
                continue;
            }

            assert!(
                local.contains(&mac),
                "{name}'s address {mac} is missing from the ignore set — \
                 this host would record itself as a nearby device"
            );
            real_addresses += 1;
        }

        assert!(
            real_addresses > 0,
            "found no interface with a real address, so this test asserted \
             nothing about the ignore set"
        );
    }

    #[test]
    fn garbage_input_is_rejected_not_fatal() {
        let cfg = WifiConfig::default();
        let stats = WifiStats::default();
        assert!(decode(&[], true, &cfg, &stats, &none()).is_none());
        assert!(decode(&[0xff; 40], true, &cfg, &stats, &none()).is_none());
    }
}
