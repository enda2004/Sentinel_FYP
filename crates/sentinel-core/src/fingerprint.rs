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

/// Everything we managed to extract from one captured frame or advertisement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "radio", rename_all = "snake_case")]
pub enum Evidence {
    Wifi(WifiEvidence),
    Ble(BleEvidence),
}

impl Evidence {
    pub fn radio(&self) -> Radio {
        match self {
            Evidence::Wifi(_) => Radio::Wifi,
            Evidence::Ble(_) => Radio::Ble,
        }
    }

    /// A short human-readable description, for display.
    pub fn describe(&self) -> String {
        match self {
            Evidence::Wifi(w) => match w.frame {
                WifiFrame::Beacon => format!("AP \"{}\"", w.ssid.as_deref().unwrap_or("<hidden>")),
                WifiFrame::AssociatedClient => "associated client".to_string(),
                WifiFrame::ProbeRequest => {
                    if w.directed_ssids.is_empty() {
                        format!("probe ({} IEs)", w.ie_order.len())
                    } else {
                        format!("probe for {}", w.directed_ssids.join(", "))
                    }
                }
            },
            Evidence::Ble(b) => {
                if let Some(name) = &b.local_name {
                    name.clone()
                } else if let Some(v) = b.vendor_name() {
                    format!("{v} device")
                } else if !b.service_uuids.is_empty() {
                    format!("BLE svc {}", b.service_uuids[0])
                } else {
                    "BLE advertiser".to_string()
                }
            }
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

/// Fingerprintable attributes of a BLE advertisement.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BleEvidence {
    /// Advertising flags (AD type 0x01).
    pub flags: Option<u8>,
    /// AD structure types in transmission order - a firmware trait, same role
    /// as the Wi-Fi IE ordering.
    pub ad_order: Vec<u8>,
    /// Advertised service UUIDs, rendered short-form where possible.
    pub service_uuids: Vec<String>,
    /// Company identifier from manufacturer-specific data (AD type 0xff).
    pub company_id: Option<u16>,
    /// First bytes of the manufacturer payload. For Apple these are Continuity
    /// message types, which differ between a phone, a watch and earbuds.
    pub mfg_prefix: Vec<u8>,
    /// Length of the manufacturer payload - stable per device role.
    pub mfg_len: usize,
    pub local_name: Option<String>,
    pub tx_power: Option<i8>,
    /// True when the report was a scan response rather than an advertisement.
    pub scan_response: bool,
}

impl BleEvidence {
    pub fn signature(&self) -> u64 {
        let mut buf: Vec<u8> = Vec::with_capacity(64);
        buf.push(self.flags.unwrap_or(0xee));
        buf.extend_from_slice(&self.ad_order);
        buf.push(0xff);
        if let Some(c) = self.company_id {
            buf.extend_from_slice(&c.to_le_bytes());
        }
        buf.extend_from_slice(&self.mfg_prefix);
        buf.push(self.mfg_len.min(255) as u8);
        buf.push(0xff);
        let mut uuids = self.service_uuids.clone();
        uuids.sort();
        uuids.dedup();
        for u in &uuids {
            buf.extend_from_slice(u.as_bytes());
            buf.push(0x00);
        }
        // A device that advertises a fixed local name is trivially trackable, so
        // fold it in; names that embed a rotating value are uncommon.
        if let Some(n) = &self.local_name {
            buf.extend_from_slice(n.as_bytes());
        }
        fnv1a64(&buf)
    }

    /// Assigned-number lookup for a handful of vendors common in homes.
    /// Anything else is reported by its numeric ID.
    pub fn vendor_name(&self) -> Option<&'static str> {
        Some(match self.company_id? {
            0x004c => "Apple",
            0x0006 => "Microsoft",
            0x00e0 => "Google",
            0x0075 => "Samsung",
            0x0087 => "Garmin",
            0x0157 => "Huami (Amazfit)",
            0x038f => "Xiaomi",
            0x05a7 => "Sonos",
            0x0171 => "Amazon",
            0x0499 => "Ruuvi",
            0x0059 => "Nordic Semiconductor",
            0x000f => "Broadcom",
            0x0001 => "Nokia",
            0x0131 => "Cypress",
            _ => return None,
        })
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

    #[test]
    fn ble_signature_distinguishes_device_roles() {
        // A phone and a Find My tag from the same vendor differ in payload shape.
        let phone = BleEvidence {
            company_id: Some(0x004c),
            ad_order: vec![0x01, 0xff],
            mfg_prefix: vec![0x10, 0x05],
            mfg_len: 12,
            ..Default::default()
        };
        let tag = BleEvidence {
            mfg_prefix: vec![0x12, 0x19],
            mfg_len: 27,
            ..phone.clone()
        };
        assert_ne!(phone.signature(), tag.signature());
        assert_eq!(phone.vendor_name(), Some("Apple"));
    }
}
