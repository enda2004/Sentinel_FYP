//! Offline capture from recorded pcap files.
//!
//! A replay turns a recorded capture into observations without root, without
//! a monitor-mode adapter and without live traffic.

use anyhow::{Context, Result};
use chrono::Utc;
use sentinel_core::mac::MacKind;
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

#[cfg(test)]
mod tests {
    use super::*;

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
