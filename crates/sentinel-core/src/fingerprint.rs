//! Device fingerprinting.
//!
//! MAC randomisation breaks the naive "one address = one device" assumption, so
//! identity is instead derived from the *shape* of what a device broadcasts:
//! which information elements a probe request carries and in what order, which
//! BLE service UUIDs and manufacturer payloads are advertised, and so on. Those
//! attributes are a property of the radio firmware and OS build rather than of
//! the rotating address, so they survive randomisation.
//!
//! The output is a 64-bit `signature`. It is deliberately *not* unique per
//! device: two identical handsets running the same OS build will collide. That
//! ambiguity (how many addresses share one signature at once) is to be
//! measured rather than hidden.

use serde::{Deserialize, Serialize};

use crate::mac::MacAddr;

/// FNV-1a. Chosen over a cryptographic hash because signatures must stay
/// comparable across runs and versions, so the value must be stable and
/// reproducible forever; it is not a security boundary.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Radio {
    Wifi,
    Ble,
}

impl Radio {
    pub fn as_str(&self) -> &'static str {
        match self {
            Radio::Wifi => "wifi",
            Radio::Ble => "ble",
        }
    }
}

impl std::str::FromStr for Radio {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "wifi" => Ok(Radio::Wifi),
            "ble" => Ok(Radio::Ble),
            other => anyhow::bail!("unknown radio {other:?}"),
        }
    }
}

/// The 802.11 frame classes we act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiFrame {
    /// Broadcast by unassociated clients scanning for networks. Carries the
    /// richest fingerprint.
    ProbeRequest,
    /// Sent by access points. Used to inventory infrastructure, not people.
    Beacon,
    /// A client that is associated to an AP. No IE fingerprint, but the address
    /// is stable for as long as the device stays joined to that network, which
    /// makes it a dependable household identifier.
    AssociatedClient,
}

impl WifiFrame {
    pub fn as_str(&self) -> &'static str {
        match self {
            WifiFrame::ProbeRequest => "probe_request",
            WifiFrame::Beacon => "beacon",
            WifiFrame::AssociatedClient => "associated_client",
        }
    }
}

/// Fingerprintable attributes of an 802.11 frame.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct WifiEvidence {
    pub frame: WifiFrame,
    /// SSID from the frame body (beacon network name, or a directed probe).
    pub ssid: Option<String>,
    /// Networks this client is actively looking for. Highly identifying: a
    /// device that probes for "Sam-iPhone-Hotspot" is very likely Sam's.
    pub directed_ssids: Vec<String>,
    /// IE identifiers in transmission order. The ordering is a firmware trait
    /// and is the backbone of the fingerprint.
    pub ie_order: Vec<u8>,
    /// Vendor-specific IE OUIs (element 221), e.g. Apple, Microsoft, WPS.
    pub vendor_ouis: Vec<[u8; 3]>,
    /// Supported rate bitmap bytes (elements 1 and 50).
    pub rates: Vec<u8>,
    /// HT / VHT / extended-capability bytes, truncated for stability.
    pub caps: Vec<u8>,
    /// BSSID for beacons and associated-client frames.
    pub bssid: Option<MacAddr>,
    /// 802.11 sequence number, kept so probe bursts can be stitched together.
    pub seq: u16,
    /// Channel the frame arrived on, if radiotap reported it.
    pub channel: Option<u16>,
}

impl Default for WifiFrame {
    fn default() -> Self {
        WifiFrame::ProbeRequest
    }
}

impl WifiEvidence {
    /// Stable hash over the attributes that do *not* change when the address
    /// rotates. SSIDs are folded in because a device's preferred-network list is
    /// itself an identifier, but they are sorted so burst ordering does not
    /// perturb the hash.
    pub fn signature(&self) -> u64 {
        let mut buf: Vec<u8> = Vec::with_capacity(96);
        buf.push(match self.frame {
            WifiFrame::ProbeRequest => 1,
            WifiFrame::Beacon => 2,
            WifiFrame::AssociatedClient => 3,
        });
        buf.extend_from_slice(&self.ie_order);
        buf.push(0xff);
        buf.extend_from_slice(&self.rates);
        buf.push(0xff);
        buf.extend_from_slice(&self.caps);
        buf.push(0xff);
        for oui in &self.vendor_ouis {
            buf.extend_from_slice(oui);
        }
        buf.push(0xff);
        let mut ssids = self.directed_ssids.clone();
        ssids.sort();
        ssids.dedup();
        for s in &ssids {
            buf.extend_from_slice(s.as_bytes());
            buf.push(0x00);
        }
        fnv1a64(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(ssids: &[&str]) -> WifiEvidence {
        WifiEvidence {
            frame: WifiFrame::ProbeRequest,
            directed_ssids: ssids.iter().map(|s| s.to_string()).collect(),
            ie_order: vec![0, 1, 50, 45, 127, 221],
            vendor_ouis: vec![[0x00, 0x17, 0xf2]],
            rates: vec![0x02, 0x04, 0x0b, 0x16],
            caps: vec![0x2d, 0x40],
            ..Default::default()
        }
    }

    #[test]
    fn signature_changes_with_preferred_networks() {
        assert_ne!(probe(&["HomeNet"]).signature(), probe(&["OtherNet"]).signature());
        // ...but not with the order they were probed in.
        assert_eq!(probe(&["a", "b"]).signature(), probe(&["b", "a"]).signature());
    }
}
