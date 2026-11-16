//! Vendor lookup from the IEEE OUI registry.
//!
//! The first three octets of a *universal* MAC address are an Organisationally
//! Unique Identifier assigned by the IEEE, so they name the manufacturer. This
//! module answers "who made this?" for those addresses and, just as
//! importantly, refuses to answer for the ones where the question is
//! meaningless.
//!
//! # Why this never touches the network
//!
//! The obvious implementation is an API call to one of the public MAC-lookup
//! services. That is not acceptable here: it would send every address heard
//! to a third party, which is precisely the harm a passive monitor must
//! avoid, and it would make an offline sensor depend on the internet. The
//! registry is therefore compiled in - see `tools/build-oui-table.py`, run
//! offline against the `ieee-data` package.
//!
//! # Why most devices have no vendor, and why that is the result
//!
//! A randomised MAC sets the locally-administered bit and fills the remaining
//! bytes with random data. Those bytes are not an OUI. Looking them up returns
//! either nothing or - far worse - a real vendor that has nothing to do with
//! the device, because random bytes land inside an assigned range often enough
//! to matter. So [`vendor_for`] takes the [`MacKind`] and returns `None` for
//! anything randomised, without consulting the table at all.
//!
//! Most phones randomise, so most will get no vendor. **That is expected, not
//! a shortfall in the implementation:** address-based identification is
//! exactly what randomisation defeats, which is why devices are to be
//! identified by payload fingerprint instead. Contrast the BLE route in
//! [`crate::fingerprint::BleEvidence::vendor_name`], which reads a company ID
//! out of the advertisement payload and therefore keeps working on randomised
//! addresses - the same question, answered by a channel randomisation does not
//! close.

use crate::mac::{MacAddr, MacKind};

/// The generated registry. See the module docs and `tools/build-oui-table.py`.
static TABLE: &[u8] = include_bytes!("oui_table.bin");

const RECORD: usize = 7; // 3-byte OUI + u32 offset into the name blob
const HEADER: usize = 4; // u32 count

fn count() -> usize {
    if TABLE.len() < HEADER {
        return 0;
    }
    u32::from_le_bytes([TABLE[0], TABLE[1], TABLE[2], TABLE[3]]) as usize
}

/// Where the NUL-terminated names start.
fn blob_start() -> usize {
    HEADER + count() * RECORD
}

fn record(i: usize) -> Option<([u8; 3], usize)> {
    let at = HEADER + i * RECORD;
    let r = TABLE.get(at..at + RECORD)?;
    let offset = u32::from_le_bytes([r[3], r[4], r[5], r[6]]) as usize;
    Some(([r[0], r[1], r[2]], offset))
}

fn name_at(offset: usize) -> Option<&'static str> {
    let start = blob_start().checked_add(offset)?;
    let rest = TABLE.get(start..)?;
    let end = rest.iter().position(|b| *b == 0)?;
    std::str::from_utf8(&rest[..end]).ok()
}

/// Look up a raw OUI. Makes no judgement about whether the address it came from
/// was meaningful - use [`vendor_for`] unless you have already checked that.
pub fn oui_vendor(oui: &[u8; 3]) -> Option<&'static str> {
    let n = count();
    if n == 0 {
        return None;
    }
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (key, offset) = record(mid)?;
        match key.cmp(oui) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => return name_at(offset),
        }
    }
    None
}

/// The manufacturer of `mac`, when the address is capable of naming one.
///
/// Returns `None` for every randomised address kind. See the module docs: this
/// is deliberate, and the caller must not fall back to a raw [`oui_vendor`]
/// call to "get more coverage".
pub fn vendor_for(mac: &MacAddr, kind: MacKind) -> Option<&'static str> {
    if kind != MacKind::Universal {
        return None;
    }
    // A multicast/broadcast first octet is not a device address either.
    if mac.is_multicast() || mac.is_zero() {
        return None;
    }
    oui_vendor(&mac.oui())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_table_loaded_and_is_sorted() {
        let n = count();
        assert!(n > 30_000, "expected the full registry, got {n} entries");
        // Binary search is only correct if the generator sorted the keys.
        let mut prev = [0u8; 3];
        for i in 0..n {
            let (key, _) = record(i).unwrap();
            assert!(key > prev || i == 0, "table is not sorted at index {i}");
            prev = key;
        }
    }

    #[test]
    fn resolves_a_known_universal_address() {
        // The Pi's own Foundation prefix, and an Apple one.
        let pi = vendor_for(&mac("b8:27:eb:01:02:03"), MacKind::Universal).unwrap();
        assert!(pi.to_lowercase().contains("raspberry"), "got {pi:?}");
        let apple = vendor_for(&mac("f0:18:98:11:22:33"), MacKind::Universal).unwrap();
        assert!(apple.to_lowercase().contains("apple"), "got {apple:?}");
    }

    /// The rule the whole feature depends on. A randomised address must never
    /// be looked up, even when its random first three bytes happen to collide
    /// with a real assignment - which is exactly when a naive implementation
    /// produces a confident, wrong answer.
    #[test]
    fn a_randomised_address_never_gets_a_vendor() {
        for kind in [
            MacKind::RandomWifi,
            MacKind::BleStaticRandom,
            MacKind::BleResolvablePrivate,
            MacKind::BleNonResolvable,
        ] {
            assert_eq!(vendor_for(&mac("b2:11:22:33:44:55"), kind), None, "{kind:?}");
        }

        // Locally-administered variant of a *real* Apple OUI. The bytes resolve
        // if you ask the table directly; the address must still yield nothing.
        let looks_like_apple = mac("f2:18:98:11:22:33");
        assert!(looks_like_apple.is_locally_administered());
        assert_eq!(
            vendor_for(&looks_like_apple, MacKind::RandomWifi),
            None,
            "a randomised address must not be resolved even by accident"
        );
    }

    /// An OUI that is genuinely unassigned must come back as `None`, not as the
    /// nearest neighbour in the table - a binary search that returned the
    /// insertion point instead of a miss would name the wrong manufacturer with
    /// total confidence.
    ///
    /// `00:ff:ff` is unassigned, unicast (bit 0 clear) and universal (bit 1
    /// clear), so it reaches the lookup rather than being rejected earlier.
    /// Note `00:00:00` is *not* a valid negative case: the IEEE really does
    /// assign it, to Xerox.
    #[test]
    fn an_unassigned_oui_returns_none_rather_than_a_guess() {
        assert_eq!(oui_vendor(&[0x00, 0xff, 0xff]), None);
        assert_eq!(vendor_for(&mac("00:ff:ff:11:22:33"), MacKind::Universal), None);
        // ...while its immediate neighbours in the table do resolve, proving
        // the search reached the right place and reported a miss.
        assert!(oui_vendor(&[0x00, 0x00, 0x00]).is_some(), "00:00:00 is Xerox");
    }

    #[test]
    fn multicast_and_zero_addresses_are_not_devices() {
        assert_eq!(vendor_for(&MacAddr::ZERO, MacKind::Universal), None);
        assert_eq!(vendor_for(&mac("01:00:5e:00:00:01"), MacKind::Universal), None);
    }

    /// Names come out of the registry as UTF-8 and are meant to be shown as
    /// they are, so they must never contain a NUL or control character.
    #[test]
    fn names_are_clean_utf8() {
        for i in (0..count()).step_by(97) {
            let (_, offset) = record(i).unwrap();
            let name = name_at(offset).expect("every record must name a vendor");
            assert!(!name.is_empty());
            assert!(
                !name.chars().any(|c| c.is_control()),
                "control character in {name:?}"
            );
        }
    }
}
