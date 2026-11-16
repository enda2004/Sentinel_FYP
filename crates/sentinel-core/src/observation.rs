//! The single value type meant to flow from every capture source into the engine.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::fingerprint::{derive_key, DeviceKey, Evidence, Radio};
use crate::mac::{MacAddr, MacKind};

/// One sighting of one device by one radio at one instant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub ts: DateTime<Utc>,
    pub mac: MacAddr,
    pub mac_kind: MacKind,
    /// Received signal strength in dBm. Absent when it was not reported (some
    /// radiotap headers omit it).
    pub rssi: Option<i8>,
    pub evidence: Evidence,
}

impl Observation {
    pub fn radio(&self) -> Radio {
        self.evidence.radio()
    }

    pub fn key(&self) -> DeviceKey {
        derive_key(&self.mac, self.mac_kind, &self.evidence)
    }

    pub fn signature(&self) -> u64 {
        match &self.evidence {
            Evidence::Wifi(w) => w.signature(),
            Evidence::Ble(b) => b.signature(),
        }
    }

    pub fn entropy(&self) -> f64 {
        match &self.evidence {
            Evidence::Wifi(w) => w.entropy_score(),
            Evidence::Ble(b) => b.entropy_score(),
        }
    }

    /// True for frames emitted by fixed infrastructure rather than by a person's
    /// device. These are to be inventoried, and must never trigger an alarm.
    pub fn is_infrastructure(&self) -> bool {
        matches!(
            &self.evidence,
            Evidence::Wifi(w) if w.frame == crate::fingerprint::WifiFrame::Beacon
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::{BleEvidence, WifiEvidence, WifiFrame};

    fn wifi(frame: WifiFrame) -> Observation {
        Observation {
            ts: chrono::Utc::now(),
            mac: "b2:11:22:33:44:55".parse().unwrap(),
            mac_kind: MacKind::RandomWifi,
            rssi: Some(-50),
            evidence: Evidence::Wifi(WifiEvidence {
                frame,
                ..Default::default()
            }),
        }
    }

    /// One line, but it decides whether a device can ever raise an alarm: an
    /// observation classified as infrastructure is to be inventoried and then
    /// ignored when deciding on alerts.
    ///
    /// Only a beacon is infrastructure. An associated-client frame comes from
    /// a device joined to a network — a laptop, not an access point — and an
    /// intruder's phone must never fall into this bucket.
    #[test]
    fn only_a_beacon_counts_as_infrastructure() {
        assert!(
            wifi(WifiFrame::Beacon).is_infrastructure(),
            "a beacon is an access point announcing itself"
        );

        for frame in [WifiFrame::ProbeRequest, WifiFrame::AssociatedClient] {
            assert!(
                !wifi(frame).is_infrastructure(),
                "{frame:?} must stay alarm-eligible"
            );
        }
    }

    /// BLE has no beacon frame type in this model, so no BLE advertisement is
    /// ever infrastructure — including one from a fixed device like a TV, which
    /// has to be handled another way, as known background.
    #[test]
    fn no_bluetooth_advertisement_is_ever_infrastructure() {
        let obs = Observation {
            ts: chrono::Utc::now(),
            mac: "40:a0:00:00:00:02".parse().unwrap(),
            mac_kind: MacKind::BleResolvablePrivate,
            rssi: Some(-70),
            evidence: Evidence::Ble(BleEvidence {
                local_name: Some("Living Room TV".into()),
                ..Default::default()
            }),
        };
        assert!(!obs.is_infrastructure());
        assert_eq!(obs.radio(), Radio::Ble);
    }

    /// `radio()` decides which radio an observation counts for, so a
    /// misrouted observation would count for the wrong radio.
    #[test]
    fn the_radio_follows_the_evidence_not_the_address() {
        assert_eq!(wifi(WifiFrame::ProbeRequest).radio(), Radio::Wifi);
        assert_eq!(wifi(WifiFrame::Beacon).radio(), Radio::Wifi);
    }
}
