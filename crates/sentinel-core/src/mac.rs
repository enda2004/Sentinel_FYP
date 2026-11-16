//! Hardware address handling.
//!
//! The whole project hinges on how much you can trust a MAC address, so the
//! distinction between a burned-in (universal) address and a randomised one is
//! modelled explicitly rather than left implicit at the call sites.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A 48-bit hardware address (802.11 MAC or Bluetooth device address).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const ZERO: MacAddr = MacAddr([0; 6]);
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    pub fn from_slice(b: &[u8]) -> Option<Self> {
        if b.len() < 6 {
            return None;
        }
        let mut a = [0u8; 6];
        a.copy_from_slice(&b[..6]);
        Some(MacAddr(a))
    }

    /// Bit 1 of the first octet: set means the address is locally administered,
    /// which for a client device in practice means "randomised".
    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }

    /// Organisationally Unique Identifier - only meaningful for universal addresses.
    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    pub fn oui_string(&self) -> String {
        format!("{:02X}:{:02X}:{:02X}", self.0[0], self.0[1], self.0[2])
    }

    pub fn bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid MAC address: {0}")]
pub struct ParseMacError(String);

impl FromStr for MacAddr {
    type Err = ParseMacError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if cleaned.len() != 12 {
            return Err(ParseMacError(s.to_string()));
        }
        let mut out = [0u8; 6];
        for (i, chunk) in cleaned.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).ok_or_else(|| ParseMacError(s.into()))?;
            let lo = (chunk[1] as char).to_digit(16).ok_or_else(|| ParseMacError(s.into()))?;
            out[i] = ((hi << 4) | lo) as u8;
        }
        Ok(MacAddr(out))
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// How much identity an address actually carries.
///
/// `Universal` addresses are burned in and uniquely identify hardware forever.
/// Everything else rotates on a timer and is only useful when combined with a
/// payload fingerprint (see [`crate::fingerprint`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacKind {
    /// Globally unique, assigned by the vendor. Strong identifier.
    Universal,
    /// 802.11 locally administered address - a randomised Wi-Fi MAC.
    RandomWifi,
    /// BLE static random address: random but stable until the device reboots.
    BleStaticRandom,
    /// BLE resolvable private address: rotates every ~15 minutes.
    BleResolvablePrivate,
    /// BLE non-resolvable private address: rotates and cannot be resolved at all.
    BleNonResolvable,
}

impl MacKind {
    /// Classify an 802.11 address.
    pub fn classify_wifi(mac: &MacAddr) -> MacKind {
        if mac.is_locally_administered() {
            MacKind::RandomWifi
        } else {
            MacKind::Universal
        }
    }

    /// Classify a Bluetooth device address.
    ///
    /// `addr_type` is the value from the HCI advertising report: 0 = public,
    /// 1 = random. For random addresses the top two bits of the most significant
    /// octet encode the sub-type (Core Spec Vol 6, Part B, 1.3.2).
    pub fn classify_ble(mac: &MacAddr, addr_type: u8) -> MacKind {
        if addr_type == 0 {
            return MacKind::Universal;
        }
        match mac.0[0] >> 6 {
            0b11 => MacKind::BleStaticRandom,
            0b01 => MacKind::BleResolvablePrivate,
            0b00 => MacKind::BleNonResolvable,
            _ => MacKind::BleNonResolvable,
        }
    }

    /// True when the address alone is a dependable long-term identifier.
    pub fn is_stable_identifier(&self) -> bool {
        matches!(self, MacKind::Universal | MacKind::BleStaticRandom)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MacKind::Universal => "universal",
            MacKind::RandomWifi => "random_wifi",
            MacKind::BleStaticRandom => "ble_static_random",
            MacKind::BleResolvablePrivate => "ble_rpa",
            MacKind::BleNonResolvable => "ble_nrpa",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_renders() {
        let m: MacAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
        assert_eq!(m.0, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(m.to_string(), "aa:bb:cc:dd:ee:ff");
        assert_eq!("aabbccddeeff".parse::<MacAddr>().unwrap(), m);
        assert!("nope".parse::<MacAddr>().is_err());
    }

    #[test]
    fn detects_randomised_wifi_addresses() {
        let random: MacAddr = "b2:00:00:00:00:01".parse().unwrap();
        let burned: MacAddr = "b8:27:eb:00:00:01".parse().unwrap();
        assert!(random.is_locally_administered());
        assert!(!burned.is_locally_administered());
        assert_eq!(MacKind::classify_wifi(&random), MacKind::RandomWifi);
        assert_eq!(MacKind::classify_wifi(&burned), MacKind::Universal);
    }

    #[test]
    fn classifies_ble_address_subtypes() {
        let rpa: MacAddr = "40:11:22:33:44:55".parse().unwrap(); // 0b01......
        let static_random: MacAddr = "c0:11:22:33:44:55".parse().unwrap(); // 0b11......
        let nrpa: MacAddr = "10:11:22:33:44:55".parse().unwrap(); // 0b00......
        assert_eq!(MacKind::classify_ble(&rpa, 1), MacKind::BleResolvablePrivate);
        assert_eq!(MacKind::classify_ble(&static_random, 1), MacKind::BleStaticRandom);
        assert_eq!(MacKind::classify_ble(&nrpa, 1), MacKind::BleNonResolvable);
        assert_eq!(MacKind::classify_ble(&rpa, 0), MacKind::Universal);
    }

    /// `from_slice` takes buffers whose length came off the wire. A short
    /// slice must be `None` rather than a panic — the release profile sets
    /// `panic = "abort"`, so an out-of-range index in this function would be a
    /// remotely-triggerable kill of the whole process.
    #[test]
    fn from_slice_refuses_a_short_buffer_rather_than_panicking() {
        for len in 0..6 {
            assert_eq!(
                MacAddr::from_slice(&vec![0xaa; len]),
                None,
                "{len} bytes is not an address"
            );
        }
        assert_eq!(
            MacAddr::from_slice(&[1, 2, 3, 4, 5, 6]).unwrap().0,
            [1, 2, 3, 4, 5, 6]
        );

        // Deliberately pinned: a *longer* slice is accepted and silently
        // truncated to the first six bytes. Callers are meant to slice exactly
        // six bytes out of a frame, so this is harmless — but it is
        // behaviour, not a guarantee, and a caller that passed a whole frame
        // would get the first six bytes of the header instead of an address.
        assert_eq!(
            MacAddr::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap().0,
            [1, 2, 3, 4, 5, 6]
        );
    }

    /// Multicast, broadcast and all-zero addresses are the three kinds that
    /// must never become a device. Getting any of them wrong would put a
    /// phantom device in the data.
    #[test]
    fn multicast_broadcast_and_zero_addresses_are_recognised() {
        let broadcast = MacAddr([0xff; 6]);
        assert!(broadcast.is_broadcast());
        assert!(
            broadcast.is_multicast(),
            "broadcast is a special case of multicast, so the multicast check \
             alone is enough to reject it"
        );
        assert!(!broadcast.is_zero());

        let zero = MacAddr([0; 6]);
        assert!(zero.is_zero());
        assert!(!zero.is_multicast(), "all-zero needs its own check");
        assert!(!zero.is_broadcast());

        // Bit 0 of the first octet is the individual/group bit, and nothing
        // else sets it. 0x01 is the IPv4-multicast OUI, 0x33 the IPv6 one.
        assert!(MacAddr([0x01, 0x00, 0x5e, 1, 2, 3]).is_multicast());
        assert!(MacAddr([0x33, 0x33, 0, 0, 0, 1]).is_multicast());

        // A real client address is none of the three, whether randomised or
        // burned in.
        for unicast in ["b2:11:22:33:44:55", "b8:27:eb:00:00:01", "fe:ff:ff:ff:ff:ff"] {
            let m: MacAddr = unicast.parse().unwrap();
            assert!(!m.is_multicast(), "{unicast}");
            assert!(!m.is_broadcast(), "{unicast}");
            assert!(!m.is_zero(), "{unicast}");
        }

        // fe:… differs from broadcast in exactly the low bit of octet 0, which
        // is the bit both checks turn on.
        assert!(!MacAddr([0xfe, 0xff, 0xff, 0xff, 0xff, 0xff]).is_broadcast());
        assert!(!MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]).is_broadcast());
    }
}
