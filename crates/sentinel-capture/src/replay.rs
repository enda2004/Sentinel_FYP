//! Offline capture sources: pcap replay and a synthetic household.
//!
//! Both let the rest of the system be developed, demonstrated and tested
//! without root, without a monitor-mode adapter and, with the synthetic
//! household, without anybody's real traffic. The household includes a
//! stranger, so that alerting on unknown devices, once it is built, will be
//! testable on demand rather than by waiting for one.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration as StdDuration;

use anyhow::{Context, Result};
use chrono::Utc;
use sentinel_core::fingerprint::{BleEvidence, Evidence, WifiEvidence, WifiFrame};
use sentinel_core::mac::{MacAddr, MacKind};
use sentinel_core::observation::Observation;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::{dot11, radiotap};

/// What a replay actually managed to read.
///
/// `frames` alone is not enough, because a damaged file makes it a *floor*
/// rather than a total. See [`truncated`](Self::truncated).
#[derive(Debug, Clone)]
pub struct ReplayOutcome {
    /// Frames successfully decoded and sent on as observations.
    pub frames: usize,
    /// `None` on a clean end of file. `Some(reason)` when the capture stopped
    /// because the file could not be read further - the usual cause being a
    /// `tcpdump` killed mid-write, or a full disk. When this is set, `frames`
    /// is a lower bound, and so is any count derived from it.
    pub truncated: Option<String>,
}

impl ReplayOutcome {
    pub fn is_complete(&self) -> bool {
        self.truncated.is_none()
    }
}

/// Replay a pcap file captured earlier with `tcpdump -i wlan1 -w capture.pcap`.
///
/// Timestamps come from the file, so replaying the same file always gives
/// the same observations at the same times.
///
/// A damaged file is still replayed as far as it goes, because a partial
/// capture is usually better than none - but the truncation is reported rather
/// than swallowed: a short replay must never look like a complete one.
pub fn replay_pcap(path: &std::path::Path, tx: Sender<Observation>) -> Result<ReplayOutcome> {
    let mut cap = pcap::Capture::from_file(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let linktype = cap.get_datalink();
    let has_radiotap = linktype == pcap::Linktype::IEEE802_11_RADIOTAP;
    if !has_radiotap && linktype != pcap::Linktype::IEEE802_11 {
        anyhow::bail!(
            "{} has link type {:?}; expected 802.11, with or without radiotap",
            path.display(),
            linktype
        );
    }
    let mut count = 0usize;
    let mut truncated = None;

    loop {
        let packet = match cap.next_packet() {
            Ok(p) => p,
            // The only clean way to finish.
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                // Not fatal - what was read is still usable - but it must not
                // be mistaken for the whole file.
                warn!(
                    file = %path.display(),
                    frames = count,
                    "capture file ended early: {e}"
                );
                truncated = Some(e.to_string());
                break;
            }
        };

        let ts = chrono::DateTime::from_timestamp(
            packet.header.ts.tv_sec as i64,
            packet.header.ts.tv_usec as u32 * 1000,
        )
        .unwrap_or_else(Utc::now);

        let (body, rssi, channel) = if has_radiotap {
            match radiotap::parse(packet.data) {
                Some(rt) if !rt.bad_fcs => match rt.frame(packet.data) {
                    Some(b) => (b, rt.signal_dbm, rt.channel()),
                    None => continue,
                },
                _ => continue,
            }
        } else {
            (packet.data, None, None)
        };

        let Some(frame) = dot11::parse(body, channel, true) else {
            continue;
        };
        let mac = frame.transmitter;
        if mac.is_multicast() || mac.is_zero() {
            continue;
        }
        let obs = Observation {
            ts,
            mac,
            mac_kind: MacKind::classify_wifi(&mac),
            rssi,
            evidence: frame.into_evidence(),
        };
        if tx.blocking_send(obs).is_err() {
            break;
        }
        count += 1;
    }
    info!(
        frames = count,
        truncated = truncated.is_some(),
        "pcap replay finished"
    );
    Ok(ReplayOutcome {
        frames: count,
        truncated,
    })
}

/// A scripted device belonging to the simulated household.
struct SimDevice {
    label: &'static str,
    radio: SimRadio,
    /// Base address; randomising devices rotate it on `rotate_secs`.
    address: MacAddr,
    rotate_secs: i64,
    /// Minutes past the hour the owner is at home, as (start, end) pairs on a
    /// 60-minute loop. Keeps one loop short.
    at_home: &'static [(i64, i64)],
    rssi: i8,
}

enum SimRadio {
    /// A client that probes for each network on its preferred-network list in
    /// turn, one SSID per frame - which is how a real probe request works, and
    /// why a device's whole list is only visible across a burst of them.
    ///
    /// Several networks per device, as real clients have.
    WifiProbe { ssids: &'static [&'static str] },
    Ble { company: u16, prefix: [u8; 2], name: Option<&'static str> },
}

/// Produce observations from a scripted household.
///
/// Three residents' devices come and go on a one-hour loop, sped up by
/// `speed`; a neighbour's television is permanently in range at low signal,
/// and a stranger's phone appears for ten minutes near the end of every loop.
/// The phones and the watch rotate their addresses every fifteen simulated
/// minutes (the laptop and the television keep theirs), so filing by
/// fingerprint has rotating addresses to follow.
pub fn run_synthetic(
    tx: Sender<Observation>,
    shutdown: Arc<AtomicBool>,
    speed: f64,
) -> Result<()> {
    let devices = vec![
        SimDevice {
            label: "resident-a-phone",
            // A phone's saved-network list: home, work, and a cafe it joined
            // once. Three networks are already close to a location history.
            radio: SimRadio::WifiProbe {
                ssids: &["HomeNet", "WorkNet", "CafeWiFi"],
            },
            address: "b2:a0:00:00:00:01".parse().unwrap(),
            rotate_secs: 900,
            at_home: &[(0, 25), (40, 60)],
            rssi: -48,
        },
        SimDevice {
            label: "resident-a-watch",
            radio: SimRadio::Ble {
                company: 0x004c,
                prefix: [0x10, 0x05],
                name: None,
            },
            address: "40:a0:00:00:00:02".parse().unwrap(),
            rotate_secs: 900,
            at_home: &[(0, 25), (40, 60)],
            rssi: -55,
        },
        SimDevice {
            label: "resident-b-phone",
            radio: SimRadio::Ble {
                company: 0x0075,
                prefix: [0x42, 0x01],
                name: None,
            },
            address: "40:b0:00:00:00:03".parse().unwrap(),
            rotate_secs: 900,
            at_home: &[(10, 55)],
            rssi: -52,
        },
        SimDevice {
            label: "resident-c-laptop",
            radio: SimRadio::WifiProbe {
                ssids: &["LibraryWiFi", "HomeNet"],
            },
            address: "8a:c0:00:00:00:04".parse().unwrap(),
            // This laptop keeps one randomised address instead of rotating it.
            rotate_secs: 0,
            at_home: &[(5, 50)],
            rssi: -60,
        },
        SimDevice {
            label: "neighbour-tv",
            radio: SimRadio::Ble {
                company: 0x0075,
                prefix: [0x02, 0x00],
                name: Some("Living Room TV"),
            },
            address: "c0:d0:00:00:00:05".parse().unwrap(),
            rotate_secs: 0,
            at_home: &[(0, 60)],
            rssi: -88,
        },
        SimDevice {
            label: "stranger-phone",
            radio: SimRadio::Ble {
                company: 0x00e0,
                prefix: [0x21, 0x03],
                name: None,
            },
            address: "40:f0:00:00:00:06".parse().unwrap(),
            rotate_secs: 900,
            at_home: &[(48, 58)],
            rssi: -44,
        },
    ];

    info!(
        devices = devices.len(),
        speed, "synthetic capture running (no radio hardware in use)"
    );
    // Naming the cast makes a run readable afterwards - otherwise the
    // only trace of which scripted device produced a sighting is its address,
    // which for the rotating ones changes every fifteen simulated minutes.
    for d in &devices {
        info!(
            device = d.label,
            radio = match d.radio {
                SimRadio::WifiProbe { .. } => "wifi",
                SimRadio::Ble { .. } => "ble",
            },
            rotate_secs = d.rotate_secs,
            rssi = d.rssi,
            "simulated household member"
        );
    }

    let start = Utc::now();
    let mut counter: i64 = 0;

    while !shutdown.load(Ordering::Relaxed) {
        // The *schedule* advances `speed` times faster than the wall clock, so
        // the household loop and the address-rotation epochs stay short.
        // Observation timestamps must not: they stay in real time, because
        // anything that ages sightings against the clock must never be handed
        // one from the future.
        let elapsed = (Utc::now() - start).num_milliseconds() as f64 / 1000.0 * speed;
        let minute = (elapsed as i64 / 60) % 60;

        for dev in &devices {
            if !dev.at_home.iter().any(|(s, e)| minute >= *s && minute < *e) {
                continue;
            }
            let mut address = dev.address;
            if dev.rotate_secs > 0 {
                // Rotate octets 3 and 4 on schedule; the last octet stays
                // fixed so no two scripted devices collide. (A real device
                // re-randomises everything but the address-type bits.)
                let epoch = (elapsed as i64) / dev.rotate_secs;
                address.0[3] = (epoch & 0xff) as u8;
                address.0[4] = ((epoch >> 8) & 0xff) as u8;
                address.0[5] = dev.address.0[5];
            }
            // A little jitter, so signal readings vary as real ones do.
            let jitter = ((counter * 37) % 7) as i8 - 3;

            let (mac_kind, evidence) = match &dev.radio {
                SimRadio::WifiProbe { ssids } => {
                    // One network per frame, cycling through the list. A real
                    // probe request carries a single SSID information element,
                    // so a client's whole preferred-network list only emerges
                    // across a burst of frames - and because the SSID is folded
                    // into the fingerprint, each network gives a fingerprint of
                    // its own. The simulation reproduces that split.
                    let ssid = ssids[(counter as usize) % ssids.len()];
                    (
                        if dev.rotate_secs > 0 {
                            MacKind::RandomWifi
                        } else {
                            MacKind::classify_wifi(&address)
                        },
                        Evidence::Wifi(WifiEvidence {
                            frame: WifiFrame::ProbeRequest,
                            directed_ssids: vec![ssid.to_string()],
                            ie_order: vec![0, 1, 50, 45, 127, 221],
                            vendor_ouis: vec![[0x00, 0x17, 0xf2]],
                            rates: vec![0x02, 0x04, 0x0b, 0x16],
                            caps: vec![0x2d, 0x40, dev.address.0[1]],
                            channel: Some(6),
                            ..Default::default()
                        }),
                    )
                }
                SimRadio::Ble {
                    company,
                    prefix,
                    name,
                } => (
                    MacKind::classify_ble(&address, 1),
                    Evidence::Ble(BleEvidence {
                        flags: Some(0x1a),
                        ad_order: vec![0x01, 0xff],
                        company_id: Some(*company),
                        mfg_prefix: prefix.to_vec(),
                        mfg_len: 12,
                        local_name: name.map(|s| s.to_string()),
                        ..Default::default()
                    }),
                ),
            };

            let obs = Observation {
                ts: Utc::now(),
                mac: address,
                mac_kind,
                rssi: Some(dev.rssi + jitter),
                evidence,
            };
            if tx.blocking_send(obs).is_err() {
                return Ok(());
            }
        }

        counter += 1;
        thread::sleep(StdDuration::from_millis(500));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn synthetic_source_produces_distinguishable_devices() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let shutdown = Arc::new(AtomicBool::new(false));
        let s = shutdown.clone();
        // 600x speed: one simulated hour per six real seconds.
        let handle = std::thread::spawn(move || run_synthetic(tx, s, 600.0));

        let mut keys = std::collections::HashSet::new();
        for _ in 0..40 {
            match tokio::time::timeout(StdDuration::from_secs(3), rx.recv()).await {
                Ok(Some(obs)) => {
                    keys.insert(obs.key().as_string());
                }
                _ => break,
            }
        }
        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();

        assert!(
            keys.len() >= 2,
            "expected several distinct simulated identities, got {keys:?}"
        );
    }

    // ------------------------------------------------------- pcap replay

    /// LINKTYPE_IEEE802_11 - bare 802.11 with no radiotap header, so the
    /// frames below are the whole packet.
    const LINKTYPE_IEEE802_11: u32 = 105;

    fn pcap_global_header() -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic, microsecond
        h.extend_from_slice(&2u16.to_le_bytes()); // version major
        h.extend_from_slice(&4u16.to_le_bytes()); // version minor
        h.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        h.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        h.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        h.extend_from_slice(&LINKTYPE_IEEE802_11.to_le_bytes());
        h
    }

    fn pcap_record(ts_sec: u32, payload: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&ts_sec.to_le_bytes());
        r.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        r.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // incl_len
        r.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // orig_len
        r.extend_from_slice(payload);
        r
    }

    /// A probe request for `ssid` from `addr2`, which is what `replay_pcap`
    /// turns into one `Observation`.
    fn probe_request(addr2: [u8; 6], ssid: &str) -> Vec<u8> {
        let mut f = vec![0u8; 24];
        f[0] = 0x40; // management, subtype 4 (probe request)
        f[4..10].copy_from_slice(&[0xff; 6]); // addr1: broadcast
        f[10..16].copy_from_slice(&addr2); // addr2: transmitter
        f[16..22].copy_from_slice(&[0xff; 6]); // addr3: BSSID
        f.push(0); // IE tag 0: SSID
        f.push(ssid.len() as u8);
        f.extend_from_slice(ssid.as_bytes());
        f
    }

    fn temp_pcap(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        // Tests write to the OS temp directory and remove their files after.
        let dir = std::env::temp_dir().join(format!("sentinel-replay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    async fn drain(path: &std::path::Path) -> (Result<ReplayOutcome>, usize) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let p = path.to_path_buf();
        let handle = std::thread::spawn(move || replay_pcap(&p, tx));
        let mut received = 0usize;
        while rx.recv().await.is_some() {
            received += 1;
        }
        (handle.join().unwrap(), received)
    }

    #[tokio::test]
    async fn replay_reads_every_frame_of_a_well_formed_file() {
        let mut bytes = pcap_global_header();
        for i in 0..3u32 {
            bytes.extend_from_slice(&pcap_record(
                1_700_000_000 + i,
                &probe_request([0xb2, 0x11, 0x22, 0x33, 0x44, 0x55], "HomeNet"),
            ));
        }
        let path = temp_pcap("good.pcap", &bytes);

        let (result, received) = drain(&path).await;
        let outcome = result.unwrap();
        assert_eq!(outcome.frames, 3, "all three frames should be replayed");
        assert_eq!(received, 3, "and all three should be sent on");
        assert!(
            outcome.is_complete(),
            "an intact file must not be reported as truncated: {:?}",
            outcome.truncated
        );

        std::fs::remove_file(&path).ok();
    }

    /// A pcap cut off mid-record - what a `tcpdump` killed mid-write, or a
    /// full disk, leaves behind - must be told apart from one that ended
    /// cleanly. A loop that treats every read error as a clean end of file
    /// cannot do that, so a short replay would look like a complete one.
    ///
    /// The file is still replayed as far as it goes, because a partial capture
    /// beats none, but it must never be indistinguishable from a complete one.
    #[tokio::test]
    async fn a_truncated_pcap_is_replayed_but_reported_as_truncated() {
        let frame = probe_request([0xb2, 0x11, 0x22, 0x33, 0x44, 0x55], "HomeNet");
        let mut bytes = pcap_global_header();
        bytes.extend_from_slice(&pcap_record(1_700_000_000, &frame)); // intact
        bytes.extend_from_slice(&pcap_record(1_700_000_001, &frame)); // intact
        // A third record header that promises a frame, followed by only four
        // bytes of it. This is exactly what a capture interrupted mid-write
        // looks like on disk.
        let mut truncated = pcap_record(1_700_000_002, &frame);
        truncated.truncate(16 + 4);
        bytes.extend_from_slice(&truncated);
        let path = temp_pcap("truncated.pcap", &bytes);

        let (result, received) = drain(&path).await;
        let outcome = result.expect("a damaged file is still replayed as far as it goes");

        assert_eq!(outcome.frames, 2, "only the two intact frames are readable");
        assert_eq!(received, 2, "and both are still sent on");

        // The whole point: the caller can tell.
        assert!(
            !outcome.is_complete(),
            "a truncated capture reported itself as complete"
        );
        let reason = outcome.truncated.expect("a reason must be given");
        assert!(
            reason.contains("truncated"),
            "the reason should say what libpcap said, got {reason:?}"
        );

        // And a clean end of file must not be mistaken for damage either.
        let mut intact = pcap_global_header();
        intact.extend_from_slice(&pcap_record(1_700_000_000, &frame));
        let intact_path = temp_pcap("intact-control.pcap", &intact);
        let (control, _) = drain(&intact_path).await;
        assert!(control.unwrap().is_complete());

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&intact_path).ok();
    }

    /// A file that is not a pcap at all must be an error rather than a panic -
    /// the release profile sets `panic = "abort"`, so a panic here would take
    /// the whole program down.
    #[tokio::test]
    async fn a_file_that_is_not_a_pcap_is_an_error_not_a_panic() {
        for (name, bytes) in [
            ("empty.pcap", Vec::new()),
            ("text.pcap", b"this is not a pcap file at all".to_vec()),
            ("header-only.pcap", pcap_global_header()[..12].to_vec()),
            ("bad-magic.pcap", {
                let mut h = pcap_global_header();
                h[0..4].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
                h
            }),
        ] {
            let path = temp_pcap(name, &bytes);
            let (result, received) = drain(&path).await;
            assert!(result.is_err(), "{name} was accepted as a capture file");
            assert_eq!(received, 0, "{name} produced observations");
            std::fs::remove_file(&path).ok();
        }

        // A pcap with a valid header and no records is legitimate: zero frames,
        // no error.
        let path = temp_pcap("no-records.pcap", &pcap_global_header());
        let (result, received) = drain(&path).await;
        let outcome = result.unwrap();
        assert_eq!(outcome.frames, 0);
        assert!(outcome.is_complete(), "an empty capture is complete, not damaged");
        assert_eq!(received, 0);
        std::fs::remove_file(&path).ok();

        let path = temp_pcap("missing", b"");
        std::fs::remove_file(&path).ok();
        assert!(
            drain(&path).await.0.is_err(),
            "a nonexistent path must be an error"
        );
    }

    /// A capture of anything but 802.11 - Ethernet, say - would be decoded as
    /// garbage frames, so it is refused.
    #[tokio::test]
    async fn a_capture_that_is_not_802_11_is_refused() {
        let mut bytes = pcap_global_header();
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
        bytes.extend_from_slice(&pcap_record(
            1_700_000_000,
            &probe_request([0xb2, 0x11, 0x22, 0x33, 0x44, 0x55], "HomeNet"),
        ));
        let path = temp_pcap("ethernet.pcap", &bytes);

        let (result, received) = drain(&path).await;
        assert!(result.is_err(), "an Ethernet capture was replayed as 802.11");
        assert_eq!(received, 0);

        std::fs::remove_file(&path).ok();
    }

    /// Frames that carry no usable identity are dropped rather than recorded.
    /// A multicast or all-zero transmitter is not a device, and counting one
    /// would invent a device that does not exist.
    #[tokio::test]
    async fn frames_with_no_real_transmitter_are_skipped() {
        let mut bytes = pcap_global_header();
        bytes.extend_from_slice(&pcap_record(
            1_700_000_000,
            &probe_request([0xff; 6], "HomeNet"), // broadcast transmitter
        ));
        bytes.extend_from_slice(&pcap_record(
            1_700_000_001,
            &probe_request([0x00; 6], "HomeNet"), // all-zero transmitter
        ));
        bytes.extend_from_slice(&pcap_record(1_700_000_002, &[0u8; 10])); // too short to parse
        bytes.extend_from_slice(&pcap_record(
            1_700_000_003,
            &probe_request([0xb2, 0x11, 0x22, 0x33, 0x44, 0x55], "HomeNet"),
        ));
        let path = temp_pcap("junk-transmitters.pcap", &bytes);

        let (result, received) = drain(&path).await;
        assert_eq!(
            result.unwrap().frames,
            1,
            "only the one frame with a real transmitter counts"
        );
        assert_eq!(received, 1);

        std::fs::remove_file(&path).ok();
    }
}
