//! The wire format between a capture service and the engine.
//!
//! Newline-delimited JSON over one TCP connection per capture service: the
//! capture side writes, the engine reads. Each connection opens with a
//! [`IngestMessage::Hello`] naming the radio, then carries observations
//! interleaved with periodic [`CaptureStats`].
//!
//! Deliberately not a message broker. There is one producer per radio and one
//! consumer, both on the same host; a broker would be another service to
//! run, monitor and secure, in exchange for nothing this needs. What a broker
//! *would* give - buffering while the engine is down - belongs on the capture
//! side instead: a bounded queue that drops the oldest and counts what it
//! drops, so loss is reported rather than silent.
//!
//! JSON because [`Observation`] already derives `Serialize`, and because a
//! capture stream that can be read with `nc` and `jq` is one that can be
//! debugged on the Pi without a decoder. `serde_json` never emits a raw newline
//! (one inside an SSID is escaped as `\n`), so a line is always one message.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::observation::Observation;

/// Which capture service is on the other end of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSource {
    Wifi,
    Ble,
    /// A scripted household, for demonstrations and tests.
    Synthetic,
}

impl CaptureSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            CaptureSource::Wifi => "wifi",
            CaptureSource::Ble => "ble",
            CaptureSource::Synthetic => "synthetic",
        }
    }
}

impl fmt::Display for CaptureSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Counters a capture service reports about itself, cumulative since it
/// started. Meant to be sent every couple of seconds, so that what the radio
/// is doing can be shown, not only what reached the engine.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CaptureStats {
    /// Frames (Wi-Fi) or advertising reports (BLE) received by the radio.
    pub frames: u64,
    /// Of those, how many parsed into an observation.
    pub parsed: u64,
    /// The channel the Wi-Fi adapter is currently tuned to; 0 for BLE.
    pub channel: u64,
    /// Observations discarded because the engine was unreachable and the
    /// queue was full. Non-zero means data was lost, and must be reported.
    pub dropped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IngestMessage {
    /// The first line on every connection.
    Hello { source: CaptureSource },
    Observation { obs: Observation },
    Stats { stats: CaptureStats },
}

impl IngestMessage {
    /// One line, including the trailing newline.
    pub fn to_line(&self) -> String {
        let mut line = serde_json::to_string(self).expect("ingest messages always serialise");
        line.push('\n');
        line
    }

    pub fn from_line(line: &str) -> serde_json::Result<IngestMessage> {
        serde_json::from_str(line.trim_end())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::{Evidence, WifiEvidence, WifiFrame};
    use crate::mac::MacKind;
    use chrono::Utc;

    fn obs(ssid: &str) -> Observation {
        Observation {
            ts: Utc::now(),
            mac: "b2:11:22:33:44:55".parse().unwrap(),
            mac_kind: MacKind::RandomWifi,
            rssi: Some(-51),
            evidence: Evidence::Wifi(WifiEvidence {
                frame: WifiFrame::ProbeRequest,
                ssid: Some(ssid.into()),
                directed_ssids: vec![ssid.into()],
                ..Default::default()
            }),
        }
    }

    /// Every message survives the trip, and an observation arrives as the same
    /// device it left as - the receiving side must key on what it decodes, so
    /// a lossy encoding would silently split or merge identities.
    #[test]
    fn every_message_round_trips_through_one_line() {
        let o = obs("HomeNet");
        let messages = [
            IngestMessage::Hello { source: CaptureSource::Ble },
            IngestMessage::Observation { obs: o.clone() },
            IngestMessage::Stats {
                stats: CaptureStats { frames: 10, parsed: 7, channel: 36, dropped: 2 },
            },
        ];
        for m in &messages {
            let line = m.to_line();
            assert!(line.ends_with('\n'));
            assert_eq!(line.matches('\n').count(), 1, "exactly one line: {line:?}");
            let back = IngestMessage::from_line(&line).unwrap();
            assert_eq!(back.to_line(), line);
        }
        let IngestMessage::Observation { obs: back } =
            IngestMessage::from_line(&messages[1].to_line()).unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(back.key(), o.key());
        assert_eq!(back.ts, o.ts);
    }

    /// A network name is chosen by whoever runs the network. One containing a
    /// newline must not be able to split a message in two and inject a second,
    /// forged observation into the stream.
    #[test]
    fn a_newline_inside_an_ssid_cannot_break_the_framing() {
        let hostile = "Free WiFi\n{\"type\":\"hello\",\"source\":\"wifi\"}";
        let line = IngestMessage::Observation { obs: obs(hostile) }.to_line();
        assert_eq!(line.matches('\n').count(), 1, "the embedded newline is escaped");
        let IngestMessage::Observation { obs: back } = IngestMessage::from_line(&line).unwrap() else {
            panic!("wrong variant");
        };
        let Evidence::Wifi(w) = back.evidence else { panic!() };
        assert_eq!(w.ssid.as_deref(), Some(hostile), "and decodes to exactly what was sent");
    }

    /// Garbage is an error, never a panic: this is read from a socket.
    #[test]
    fn a_malformed_line_is_an_error_not_a_panic() {
        for bad in ["", "{}", "not json", "{\"type\":\"teleport\"}", "{\"type\":\"hello\"}"] {
            assert!(IngestMessage::from_line(bad).is_err(), "{bad:?}");
        }
    }
}
