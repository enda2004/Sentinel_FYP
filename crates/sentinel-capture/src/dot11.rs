//! 802.11 frame dissection.
//!
//! Three frame types are of interest:
//!
//! * **Probe requests** - broadcast by unassociated clients hunting for
//!   networks. Their tagged information elements are the Wi-Fi fingerprint.
//! * **Beacons** - identify access points, so they are never mistaken for
//!   people.
//! * **Data frames** - reveal clients that are already associated. Such a
//!   client's address is stable for as long as it stays joined to the network,
//!   which makes it the most dependable household identifier available.

use sentinel_core::fingerprint::{Evidence, WifiEvidence, WifiFrame};
use sentinel_core::mac::MacAddr;

const FTYPE_MGMT: u8 = 0;
const FTYPE_DATA: u8 = 2;
const SUBTYPE_PROBE_REQ: u8 = 4;
const SUBTYPE_BEACON: u8 = 8;

/// Information elements whose *contents* are folded into the fingerprint.
/// These describe fixed radio capabilities, so they are constant for a given
/// chipset and driver but differ between device models.
const FINGERPRINTED_IES: &[u8] = &[
    1,   // Supported rates
    50,  // Extended supported rates
    45,  // HT capabilities
    127, // Extended capabilities
    191, // VHT capabilities
    107, // Interworking
];

#[derive(Debug, Clone, PartialEq)]
pub struct Dot11Frame {
    pub transmitter: MacAddr,
    pub evidence: WifiEvidence,
}

/// Parse an 802.11 frame body (radiotap already stripped).
///
/// Returns `None` for frame types not acted on, or for anything malformed.
pub fn parse(buf: &[u8], channel: Option<u16>, capture_data_frames: bool) -> Option<Dot11Frame> {
    if buf.len() < 24 {
        return None;
    }
    let fc0 = buf[0];
    let fc1 = buf[1];
    let ftype = (fc0 >> 2) & 0x03;
    let subtype = (fc0 >> 4) & 0x0f;
    let to_ds = fc1 & 0x01 != 0;
    let from_ds = fc1 & 0x02 != 0;

    let addr1 = MacAddr::from_slice(&buf[4..10])?;
    let addr2 = MacAddr::from_slice(&buf[10..16])?;
    let addr3 = MacAddr::from_slice(&buf[16..22])?;
    let seq = u16::from_le_bytes([buf[22], buf[23]]) >> 4;

    match (ftype, subtype) {
        (FTYPE_MGMT, SUBTYPE_PROBE_REQ) => {
            let mut ev = parse_tagged(&buf[24..]);
            ev.frame = WifiFrame::ProbeRequest;
            ev.seq = seq;
            ev.channel = channel;
            // A probe naming a specific network is a directed probe; the
            // broadcast (empty SSID) case says nothing about preferences.
            if let Some(ssid) = ev.ssid.clone() {
                if !ssid.is_empty() {
                    ev.directed_ssids.push(ssid);
                }
            }
            Some(Dot11Frame {
                transmitter: addr2,
                evidence: ev,
            })
        }
        (FTYPE_MGMT, SUBTYPE_BEACON) => {
            // Beacon body: 8 bytes timestamp, 2 interval, 2 capability, then IEs.
            if buf.len() < 36 {
                return None;
            }
            let mut ev = parse_tagged(&buf[36..]);
            ev.frame = WifiFrame::Beacon;
            ev.seq = seq;
            ev.channel = channel;
            ev.bssid = Some(addr3);
            Some(Dot11Frame {
                transmitter: addr2,
                evidence: ev,
            })
        }
        (FTYPE_DATA, _) if capture_data_frames => {
            // Only frames travelling client -> AP identify a client. The
            // reverse direction carries the AP's address as transmitter.
            if !to_ds || from_ds {
                return None;
            }
            if addr2.is_multicast() || addr2.is_zero() {
                return None;
            }
            Some(Dot11Frame {
                transmitter: addr2,
                evidence: WifiEvidence {
                    frame: WifiFrame::AssociatedClient,
                    bssid: Some(addr1),
                    seq,
                    channel,
                    ..Default::default()
                },
            })
        }
        _ => None,
    }
}

impl Dot11Frame {
    pub fn into_evidence(self) -> Evidence {
        Evidence::Wifi(self.evidence)
    }
}

/// Walk the tagged-parameter list, recording both the ordering of the elements
/// and the contents of the ones that carry capability information.
fn parse_tagged(mut body: &[u8]) -> WifiEvidence {
    let mut ev = WifiEvidence::default();
    while body.len() >= 2 {
        let id = body[0];
        let len = body[1] as usize;
        if body.len() < 2 + len {
            break; // truncated element: stop rather than read past it
        }
        let data = &body[2..2 + len];
        ev.ie_order.push(id);

        match id {
            0 => {
                // SSID. Non-UTF-8 SSIDs exist; they are rendered lossily rather
                // than dropped so the device is still distinguishable.
                if !data.is_empty() {
                    ev.ssid = Some(String::from_utf8_lossy(data).into_owned());
                }
            }
            1 | 50 => ev.rates.extend_from_slice(data),
            221 => {
                if data.len() >= 4 {
                    ev.vendor_ouis.push([data[0], data[1], data[2]]);
                    // Include the vendor sub-type: one OUI carries several
                    // unrelated elements (WPA, WMM and WPS under Microsoft's,
                    // P2P and Hotspot 2.0 under the Wi-Fi Alliance's).
                    ev.caps.push(data[3]);
                }
            }
            _ if FINGERPRINTED_IES.contains(&id) => {
                // Truncated: the tail of extended capabilities varies with
                // transient state (e.g. operating mode), the head does not.
                ev.caps.extend_from_slice(&data[..data.len().min(6)]);
            }
            _ => {}
        }
        body = &body[2 + len..];
    }
    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ie(id: u8, data: &[u8]) -> Vec<u8> {
        let mut v = vec![id, data.len() as u8];
        v.extend_from_slice(data);
        v
    }

    fn mgmt_header(subtype: u8, src: [u8; 6]) -> Vec<u8> {
        let mut v = vec![subtype << 4, 0x00];
        v.extend_from_slice(&[0, 0]); // duration
        v.extend_from_slice(&[0xff; 6]); // addr1 broadcast
        v.extend_from_slice(&src); // addr2 transmitter
        v.extend_from_slice(&[0xff; 6]); // addr3
        v.extend_from_slice(&[0x10, 0x00]); // sequence control
        v
    }

    #[test]
    fn parses_a_directed_probe_request() {
        let mut f = mgmt_header(SUBTYPE_PROBE_REQ, [0xb2, 1, 2, 3, 4, 5]);
        f.extend(ie(0, b"HomeNet"));
        f.extend(ie(1, &[0x02, 0x04, 0x0b, 0x16]));
        f.extend(ie(45, &[0x2d, 0x40, 0x1b, 0xff]));
        f.extend(ie(221, &[0x00, 0x17, 0xf2, 0x0a, 0x00]));

        let out = parse(&f, Some(6), true).unwrap();
        assert_eq!(out.transmitter.to_string(), "b2:01:02:03:04:05");
        let ev = out.evidence;
        assert_eq!(ev.frame, WifiFrame::ProbeRequest);
        assert_eq!(ev.ssid.as_deref(), Some("HomeNet"));
        assert_eq!(ev.directed_ssids, vec!["HomeNet".to_string()]);
        assert_eq!(ev.ie_order, vec![0, 1, 45, 221]);
        assert_eq!(ev.rates, vec![0x02, 0x04, 0x0b, 0x16]);
        assert_eq!(ev.vendor_ouis, vec![[0x00, 0x17, 0xf2]]);
        assert_eq!(ev.channel, Some(6));
        assert_eq!(ev.seq, 1);
    }

    #[test]
    fn broadcast_probes_have_no_directed_ssid() {
        let mut f = mgmt_header(SUBTYPE_PROBE_REQ, [0xb2, 1, 2, 3, 4, 5]);
        f.extend(ie(0, b"")); // wildcard SSID
        f.extend(ie(1, &[0x02, 0x04]));
        let ev = parse(&f, None, true).unwrap().evidence;
        assert!(ev.directed_ssids.is_empty());
        assert_eq!(ev.ssid, None);
    }

    #[test]
    fn identifies_access_points_from_beacons() {
        let mut f = mgmt_header(SUBTYPE_BEACON, [0xb8, 0x27, 0xeb, 1, 2, 3]);
        f.extend_from_slice(&[0u8; 12]); // timestamp + interval + capability
        f.extend(ie(0, b"HomeNet"));
        let out = parse(&f, Some(11), true).unwrap();
        assert_eq!(out.evidence.frame, WifiFrame::Beacon);
        assert_eq!(out.evidence.ssid.as_deref(), Some("HomeNet"));
    }

    #[test]
    fn tracks_associated_clients_in_the_uplink_only() {
        // ToDS set: client -> AP, addr2 is the client.
        let mut up = vec![(FTYPE_DATA << 2) | 0x00, 0x01];
        up.extend_from_slice(&[0, 0]);
        up.extend_from_slice(&[0xb8, 0x27, 0xeb, 1, 2, 3]); // addr1 = BSSID
        up.extend_from_slice(&[0x8a, 0x11, 0x22, 0x33, 0x44, 0x55]); // addr2 = client
        up.extend_from_slice(&[0xff; 6]);
        up.extend_from_slice(&[0, 0]);
        let out = parse(&up, Some(1), true).unwrap();
        assert_eq!(out.evidence.frame, WifiFrame::AssociatedClient);
        assert_eq!(out.transmitter.to_string(), "8a:11:22:33:44:55");

        // FromDS set: AP -> client, transmitter is the AP. Not a client sighting.
        let mut down = up.clone();
        down[1] = 0x02;
        assert!(parse(&down, Some(1), true).is_none());

        // Disabled by configuration.
        assert!(parse(&up, Some(1), false).is_none());
    }

    #[test]
    fn truncated_elements_do_not_panic() {
        let mut f = mgmt_header(SUBTYPE_PROBE_REQ, [0xb2, 1, 2, 3, 4, 5]);
        f.extend_from_slice(&[0x00, 0x40, b'x']); // claims 64 bytes, supplies 1
        let ev = parse(&f, None, true).unwrap().evidence;
        assert!(ev.ie_order.is_empty());

        // And a frame shorter than the header.
        assert!(parse(&[0u8; 10], None, true).is_none());
    }

    #[test]
    fn identical_clients_produce_identical_signatures() {
        let mut a = mgmt_header(SUBTYPE_PROBE_REQ, [0xb2, 1, 1, 1, 1, 1]);
        let mut b = mgmt_header(SUBTYPE_PROBE_REQ, [0xbe, 9, 9, 9, 9, 9]);
        for f in [&mut a, &mut b] {
            f.extend(ie(0, b"HomeNet"));
            f.extend(ie(1, &[0x02, 0x04, 0x0b, 0x16]));
            f.extend(ie(45, &[0x2d, 0x40]));
        }
        // Different sequence numbers, as two real bursts would have.
        b[22] = 0x50;
        let sa = parse(&a, Some(6), true).unwrap().evidence.signature();
        let sb = parse(&b, Some(11), true).unwrap().evidence.signature();
        assert_eq!(sa, sb, "signature must ignore address, sequence and channel");
    }
}
