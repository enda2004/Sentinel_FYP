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

use crate::mac::{MacAddr, MacKind};

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

    /// Rough measure of how much identifying information the fingerprint holds.
    /// A probe with no IEs beyond the mandatory ones tells us almost nothing;
    /// one that names three specific networks tells us a great deal.
    pub fn entropy_score(&self) -> f64 {
        let mut score = 0.0;
        score += (self.ie_order.len() as f64).min(12.0) * 0.4;
        score += self.vendor_ouis.len() as f64 * 1.5;
        score += self.directed_ssids.len() as f64 * 3.0;
        score += if self.caps.is_empty() { 0.0 } else { 2.0 };
        score
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

    pub fn entropy_score(&self) -> f64 {
        let mut score = 0.0;
        score += (self.ad_order.len() as f64).min(8.0) * 0.6;
        score += self.service_uuids.len() as f64 * 1.5;
        score += if self.company_id.is_some() { 1.5 } else { 0.0 };
        score += (self.mfg_prefix.len() as f64).min(4.0);
        score += if self.local_name.is_some() { 3.0 } else { 0.0 };
        score
    }

    /// A *guess* at what kind of device this is, from the manufacturer payload.
    ///
    /// **This is inference, not a model number**, and the caller must present it
    /// as such. Nothing in a BLE advertisement states the product; what we have
    /// is Apple's Continuity protocol, whose first payload byte is a message
    /// type that different product classes emit at different rates. A watch
    /// broadcasts Nearby Info constantly, AirPods announce Proximity Pairing,
    /// and so on. The mapping below is the widely-documented reading of those
    /// type bytes, and it is right often enough to be useful and wrong often
    /// enough that it must never be shown as a bare fact.
    ///
    /// Only Apple is attempted. Every other vendor either does not publish a
    /// comparable structure or varies it per product line, and guessing from
    /// thin evidence would be worse than saying nothing - so everything else
    /// returns `None` rather than a speculative label.
    ///
    /// Reference: Apple Continuity message types, as documented by the
    /// furiousMAC protocol analysis (US Naval Postgraduate School).
    pub fn inferred_model(&self) -> Option<&'static str> {
        // Apple only. 0x004c is Apple's Bluetooth SIG company identifier.
        if self.company_id? != 0x004c {
            return None;
        }
        Some(match self.mfg_prefix.first()? {
            // Proximity Pairing - the earbud/accessory pairing beacon.
            0x07 => "AirPods or accessory",
            // Nearby Info. Ubiquitous across iPhone, iPad and Watch; the
            // second byte carries status flags, not a product code, so this
            // cannot be narrowed further without overclaiming.
            0x10 => "iPhone, iPad or Watch",
            // Nearby Action - AirDrop, setup prompts. Handsets and tablets.
            0x0f => "iPhone or iPad",
            // AirPrint.
            0x03 => "printer",
            // Handoff between a user's own devices.
            0x0c => "Mac, iPhone or iPad",
            // AirPlay target: Apple TV, HomePod.
            0x09 | 0x0a => "Apple TV or HomePod",
            // Find My / offline finding beacon - AirTag and anything opted in.
            0x12 => "AirTag or Find My device",
            _ => return None,
        })
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

/// The identity a device is filed under.
///
/// This is the crux of the system: when the address is trustworthy we key on
/// it, and when it is not we fall back to the payload fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeviceKey {
    /// Keyed on a hardware address that does not rotate.
    Address(Radio, MacAddr),
    /// Keyed on a payload fingerprint because the address rotates.
    Signature(Radio, u64),
}

impl DeviceKey {
    pub fn radio(&self) -> Radio {
        match self {
            DeviceKey::Address(r, _) | DeviceKey::Signature(r, _) => *r,
        }
    }

    /// Stable string form, used wherever an identity is stored or shown.
    pub fn as_string(&self) -> String {
        match self {
            DeviceKey::Address(r, m) => format!("{}:mac:{}", r.as_str(), m),
            DeviceKey::Signature(r, s) => format!("{}:sig:{:016x}", r.as_str(), s),
        }
    }

    pub fn parse(s: &str) -> Option<DeviceKey> {
        let mut parts = s.splitn(3, ':');
        let radio: Radio = parts.next()?.parse().ok()?;
        match parts.next()? {
            "mac" => Some(DeviceKey::Address(radio, parts.next()?.parse().ok()?)),
            "sig" => Some(DeviceKey::Signature(
                radio,
                u64::from_str_radix(parts.next()?, 16).ok()?,
            )),
            _ => None,
        }
    }

    /// Whether this identity is anchored to hardware or only to a fingerprint.
    pub fn is_address_bound(&self) -> bool {
        matches!(self, DeviceKey::Address(..))
    }
}

impl std::fmt::Display for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_string())
    }
}

/// Minimum entropy for a fingerprint to stand in for an address.
///
/// A fingerprint is only allowed to stand in for an address when it carries
/// enough entropy to be worth anything; below the threshold the device is keyed
/// on its (rotating) address and will simply churn, which is the honest
/// outcome - a bare probe request from a randomised MAC genuinely is untrackable.
pub const MIN_SIGNATURE_ENTROPY: f64 = 4.0;

/// Decide how to file an observation.
pub fn derive_key(mac: &MacAddr, kind: MacKind, evidence: &Evidence) -> DeviceKey {
    let radio = evidence.radio();
    if kind.is_stable_identifier() {
        return DeviceKey::Address(radio, *mac);
    }
    let (sig, entropy) = match evidence {
        Evidence::Wifi(w) => (w.signature(), w.entropy_score()),
        Evidence::Ble(b) => (b.signature(), b.entropy_score()),
    };
    if entropy >= MIN_SIGNATURE_ENTROPY {
        DeviceKey::Signature(radio, sig)
    } else {
        DeviceKey::Address(radio, *mac)
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
    fn signature_survives_address_rotation() {
        // Same device, two different randomised addresses, identical payload.
        let a = probe(&["HomeNet"]);
        let b = probe(&["HomeNet"]);
        assert_eq!(a.signature(), b.signature());

        let mac1: MacAddr = "b2:11:11:11:11:11".parse().unwrap();
        let mac2: MacAddr = "be:22:22:22:22:22".parse().unwrap();
        let k1 = derive_key(&mac1, MacKind::RandomWifi, &Evidence::Wifi(a));
        let k2 = derive_key(&mac2, MacKind::RandomWifi, &Evidence::Wifi(b));
        assert_eq!(k1, k2, "randomised addresses must collapse onto one identity");
        assert!(!k1.is_address_bound());
    }

    #[test]
    fn signature_changes_with_preferred_networks() {
        assert_ne!(probe(&["HomeNet"]).signature(), probe(&["OtherNet"]).signature());
        // ...but not with the order they were probed in.
        assert_eq!(probe(&["a", "b"]).signature(), probe(&["b", "a"]).signature());
    }

    #[test]
    fn universal_addresses_key_on_hardware() {
        let mac: MacAddr = "b8:27:eb:01:02:03".parse().unwrap();
        let k = derive_key(&mac, MacKind::Universal, &Evidence::Wifi(probe(&[])));
        assert_eq!(k, DeviceKey::Address(Radio::Wifi, mac));
        assert!(k.is_address_bound());
    }

    #[test]
    fn low_entropy_probes_are_not_promoted_to_signatures() {
        let bare = WifiEvidence {
            frame: WifiFrame::ProbeRequest,
            ie_order: vec![0, 1],
            ..Default::default()
        };
        let mac: MacAddr = "b2:11:11:11:11:11".parse().unwrap();
        let k = derive_key(&mac, MacKind::RandomWifi, &Evidence::Wifi(bare));
        assert!(k.is_address_bound(), "not enough entropy to track across rotations");
    }

    #[test]
    fn device_key_round_trips() {
        for k in [
            DeviceKey::Address(Radio::Ble, "aa:bb:cc:dd:ee:ff".parse().unwrap()),
            DeviceKey::Signature(Radio::Wifi, 0xdead_beef_0000_0001),
        ] {
            assert_eq!(DeviceKey::parse(&k.as_string()), Some(k));
        }
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

    #[test]
    fn model_inference_is_apple_only_and_admits_what_it_does_not_know() {
        let apple = |prefix: Vec<u8>| BleEvidence {
            company_id: Some(0x004c),
            mfg_prefix: prefix,
            ..Default::default()
        };
        assert_eq!(apple(vec![0x07, 0x19]).inferred_model(), Some("AirPods or accessory"));
        assert_eq!(apple(vec![0x10, 0x05]).inferred_model(), Some("iPhone, iPad or Watch"));
        assert_eq!(apple(vec![0x12, 0x19]).inferred_model(), Some("AirTag or Find My device"));

        // An Apple payload whose type byte we do not recognise must produce no
        // label at all rather than a nearest-neighbour guess.
        assert_eq!(apple(vec![0xdd]).inferred_model(), None);
        assert_eq!(apple(vec![]).inferred_model(), None);

        // Other vendors are never guessed at, however suggestive the payload.
        let samsung = BleEvidence {
            company_id: Some(0x0075),
            mfg_prefix: vec![0x10, 0x05],
            ..Default::default()
        };
        assert_eq!(samsung.inferred_model(), None);
        assert_eq!(samsung.vendor_name(), Some("Samsung"));

        // No manufacturer data at all.
        assert_eq!(BleEvidence::default().inferred_model(), None);
    }
}
