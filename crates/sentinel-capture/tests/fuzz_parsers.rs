//! Adversarial input sweep for the three over-the-air parsers.
//!
//! These parsers read untrusted input from the air, and the release profile
//! sets `panic = "abort"`, so a single panic in one of them would stop capture.

use sentinel_capture::{ble, dot11, radiotap};

/// Deterministic xorshift, so a failure is reproducible from the seed alone.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill(&mut self, buf: &mut Vec<u8>, len: usize) {
        buf.clear();
        for _ in 0..len {
            buf.push((self.next() & 0xff) as u8);
        }
    }
}

#[test]
fn parsers_survive_random_input() {
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    let mut buf = Vec::new();
    for _ in 0..200_000u32 {
        let len = (rng.next() % 300) as usize;
        rng.fill(&mut buf, len);
        let _ = radiotap::parse(&buf);
        let _ = dot11::parse(&buf, Some(6), true);
        let _ = dot11::parse(&buf, None, false);
        let _ = ble::parse_event(&buf);
    }
}

/// Random bytes almost never form a *valid-looking* header, so bias the input
/// towards structurally plausible frames: correct version, sane length, real
/// present bitmaps, real frame-control bytes, real HCI event framing.
#[test]
fn parsers_survive_structured_mutation() {
    let mut rng = Rng(0xfeed_face_dead_beef);
    let mut buf = Vec::new();

    for _ in 0..200_000u32 {
        // --- radiotap-shaped ---
        let len = 8 + (rng.next() % 60) as usize;
        rng.fill(&mut buf, len);
        buf[0] = 0; // valid version
        buf[1] = 0;
        let claimed = (rng.next() % 80) as u16;
        buf[2] = (claimed & 0xff) as u8;
        buf[3] = (claimed >> 8) as u8;
        let _ = radiotap::parse(&buf);

        // --- 802.11-shaped ---
        let len = 2 + (rng.next() % 80) as usize;
        rng.fill(&mut buf, len);
        // Real frame-control type/subtype combinations.
        buf[0] = [0x40, 0x50, 0x80, 0x08, 0x88, 0xb0, 0xc0, 0xd4]
            [(rng.next() % 8) as usize];
        let _ = dot11::parse(&buf, Some(11), true);

        // --- HCI-event-shaped ---
        let len = 3 + (rng.next() % 90) as usize;
        rng.fill(&mut buf, len);
        buf[0] = 0x04; // HCI_EVENT_PKT
        buf[1] = 0x3e; // LE Meta
        buf[2] = (len - 3) as u8; // plausible parameter length
        if len > 3 {
            buf[3] = if rng.next() % 2 == 0 { 0x02 } else { 0x0d };
        }
        let _ = ble::parse_event(&buf);
    }
}

/// Truncation sweep: every prefix of a well-formed frame must be handled
/// without panicking on a short read.
#[test]
fn every_prefix_of_a_valid_frame_is_safe() {
    let mut full = vec![0u8, 0u8, 0, 0];
    let present: u32 = (1 << 1) | (1 << 3) | (1 << 5);
    full.extend_from_slice(&present.to_le_bytes());
    full.push(0x00);
    full.push(0x00);
    full.extend_from_slice(&2437u16.to_le_bytes());
    full.extend_from_slice(&0u16.to_le_bytes());
    full.push(0xd0);
    let l = full.len() as u16;
    full[2..4].copy_from_slice(&l.to_le_bytes());
    let mut frame = vec![0x40, 0x00, 0, 0];
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&[0xb2, 1, 2, 3, 4, 5]);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0, 7]);
    frame.extend_from_slice(b"HomeNet");
    full.extend_from_slice(&frame);

    for n in 0..=full.len() {
        let _ = radiotap::parse(&full[..n]);
        let _ = dot11::parse(&full[..n], Some(6), true);
        let _ = ble::parse_event(&full[..n]);
    }
    // The 802.11 parser on its own, without the radiotap header in front.
    for n in 0..=frame.len() {
        let _ = dot11::parse(&frame[..n], Some(6), true);
    }

    // Length field claiming more than the buffer holds, at every claim value.
    for claimed in 0u16..=600 {
        let mut b = full.clone();
        b[2..4].copy_from_slice(&claimed.to_le_bytes());
        let _ = radiotap::parse(&b);
    }
}
