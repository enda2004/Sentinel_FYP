//! Minimal radiotap header parser.
//!
//! Monitor-mode captures prepend a radiotap header carrying the metadata the
//! radio recorded about the frame. Only three fields matter here - flags,
//! signal strength and channel - but radiotap fields are packed in bit order
//! with per-field alignment, so the earlier fields still have to be walked
//! over to find them.
//!
//! Reference: <https://www.radiotap.org/>

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RadiotapInfo {
    pub length: usize,
    /// Signal strength in dBm, when the adapter reported it.
    pub signal_dbm: Option<i8>,
    /// Centre frequency in MHz.
    pub frequency: Option<u16>,
    /// True when the driver flagged a failed FCS check - the frame is corrupt
    /// and must not be fingerprinted.
    pub bad_fcs: bool,
    /// True when the frame still ends with its 4-byte FCS. Some drivers keep
    /// it; read as frame data it would look like one more element.
    pub fcs_at_end: bool,
}

impl RadiotapInfo {
    /// The 802.11 frame that follows this header in `packet`, with a trailing
    /// FCS cut off. `None` if the packet is too short to hold it.
    pub fn frame<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        let body = packet.get(self.length..)?;
        if self.fcs_at_end {
            body.get(..body.len().checked_sub(4)?)
        } else {
            Some(body)
        }
    }

    /// 802.11 channel number derived from the centre frequency.
    pub fn channel(&self) -> Option<u16> {
        let f = self.frequency?;
        Some(match f {
            2412..=2472 => (f - 2407) / 5,
            2484 => 14,
            5000..=5895 => (f - 5000) / 5,
            _ => return None,
        })
    }
}

/// Size and alignment of each radiotap field, indexed by its present-bit.
/// Only the fields below bit 15 are modelled; parsing stops if anything higher
/// is needed, which is fine because signal (bit 5) and channel (bit 3) are low.
const FIELD_LAYOUT: [(usize, usize); 15] = [
    (8, 8), // 0  TSFT
    (1, 1), // 1  Flags
    (1, 1), // 2  Rate
    (4, 2), // 3  Channel
    (2, 2), // 4  FHSS
    (1, 1), // 5  dBm antenna signal
    (1, 1), // 6  dBm antenna noise
    (2, 2), // 7  Lock quality
    (2, 2), // 8  TX attenuation
    (2, 2), // 9  dB TX attenuation
    (1, 1), // 10 dBm TX power
    (1, 1), // 11 Antenna
    (1, 1), // 12 dB antenna signal
    (1, 1), // 13 dB antenna noise
    (2, 2), // 14 RX flags
];

const PRESENT_CHANNEL: u32 = 1 << 3;
const PRESENT_SIGNAL: u32 = 1 << 5;
const PRESENT_FLAGS: u32 = 1 << 1;
const PRESENT_EXT: u32 = 1 << 31;
const FLAG_FCS_AT_END: u8 = 0x10;
const FLAG_BAD_FCS: u8 = 0x40;

/// Parse the header. Returns `None` if the buffer is truncated or malformed;
/// the caller should drop such frames rather than guess at their contents.
pub fn parse(buf: &[u8]) -> Option<RadiotapInfo> {
    if buf.len() < 8 || buf[0] != 0 {
        return None; // version must be 0
    }
    let length = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    if length < 8 || length > buf.len() {
        return None;
    }

    // Walk the chain of present-bitmap words; the field data starts after it.
    let mut present_words: Vec<u32> = Vec::with_capacity(2);
    let mut off = 4;
    loop {
        if off + 4 > length {
            return None;
        }
        let word = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        present_words.push(word);
        off += 4;
        if word & PRESENT_EXT == 0 {
            break;
        }
    }

    let mut info = RadiotapInfo {
        length,
        ..Default::default()
    };

    // Only the first word's fields are decoded. Extension words describe vendor
    // namespaces and fields beyond anything needed here.
    let present = present_words[0];
    let mut cursor = off;

    for bit in 0..FIELD_LAYOUT.len() {
        let mask = 1u32 << bit;
        if present & mask == 0 {
            continue;
        }
        let (size, align) = FIELD_LAYOUT[bit];
        // Alignment is relative to the start of the radiotap header.
        let pad = (align - (cursor % align)) % align;
        cursor += pad;
        if cursor + size > length {
            return None;
        }
        match mask {
            PRESENT_FLAGS => {
                info.bad_fcs = buf[cursor] & FLAG_BAD_FCS != 0;
                info.fcs_at_end = buf[cursor] & FLAG_FCS_AT_END != 0;
            }
            PRESENT_CHANNEL => {
                info.frequency = Some(u16::from_le_bytes([buf[cursor], buf[cursor + 1]]))
            }
            PRESENT_SIGNAL => info.signal_dbm = Some(buf[cursor] as i8),
            _ => {}
        }
        cursor += size;
    }

    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Header with flags, rate, channel and signal - the shape most drivers emit.
    fn sample() -> Vec<u8> {
        let present: u32 = PRESENT_FLAGS | (1 << 2) | PRESENT_CHANNEL | PRESENT_SIGNAL;
        let mut v = vec![0u8, 0u8]; // version, pad
        // length filled in below
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(&present.to_le_bytes());
        v.push(0x00); // flags        @ offset 8, align 1
        v.push(0x02); // rate         @ offset 9, align 1
        v.extend_from_slice(&2437u16.to_le_bytes()); // channel freq @ 10, align 2
        v.extend_from_slice(&0x0080u16.to_le_bytes()); // channel flags
        v.push((-42i8) as u8); // signal @ 14
        let len = v.len() as u16;
        v[2..4].copy_from_slice(&len.to_le_bytes());
        v
    }

    #[test]
    fn extracts_signal_and_channel() {
        let info = parse(&sample()).unwrap();
        assert_eq!(info.signal_dbm, Some(-42));
        assert_eq!(info.frequency, Some(2437));
        assert_eq!(info.channel(), Some(6));
        assert!(!info.bad_fcs);
    }

    #[test]
    fn maps_5ghz_frequencies() {
        let mut buf = sample();
        buf[10..12].copy_from_slice(&5180u16.to_le_bytes());
        assert_eq!(parse(&buf).unwrap().channel(), Some(36));
    }

    #[test]
    fn flags_corrupt_frames() {
        let mut buf = sample();
        buf[8] = FLAG_BAD_FCS;
        assert!(parse(&buf).unwrap().bad_fcs);
    }

    #[test]
    fn cuts_a_trailing_fcs_off_the_frame() {
        let mut buf = sample();
        let start = buf.len();
        buf.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44]);

        let info = parse(&buf).unwrap();
        assert!(!info.fcs_at_end);
        assert_eq!(info.frame(&buf), Some(&buf[start..]));

        buf[8] = FLAG_FCS_AT_END;
        let info = parse(&buf).unwrap();
        assert!(info.fcs_at_end);
        assert_eq!(info.frame(&buf), Some(&buf[start..start + 4]), "the FCS is cut off");

        // A frame too short to hold the FCS it claims is refused.
        assert_eq!(info.frame(&buf[..start + 2]), None);
    }

    #[test]
    fn rejects_malformed_headers() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[1, 0, 8, 0, 0, 0, 0, 0]).is_none(), "bad version");
        // Length longer than the buffer.
        assert!(parse(&[0, 0, 0xff, 0x00, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn handles_extended_present_bitmaps() {
        let mut v = vec![0u8, 0u8, 0, 0];
        v.extend_from_slice(&(PRESENT_SIGNAL | PRESENT_EXT).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // second present word
        v.push((-70i8) as u8);
        let len = v.len() as u16;
        v[2..4].copy_from_slice(&len.to_le_bytes());
        assert_eq!(parse(&v).unwrap().signal_dbm, Some(-70));
    }
}
