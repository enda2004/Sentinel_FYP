//! Thin, safe-ish wrapper over a raw Bluetooth HCI socket.
//!
//! The obvious route for BLE work in Rust is `btleplug`, which talks to BlueZ
//! over D-Bus. It is not used here, because BlueZ hands back a
//! *normalised* view of a device (address, name, RSSI, resolved service list)
//! and deduplicates reports. Passive fingerprinting needs the opposite - the
//! raw advertising PDU, the address *type* (public / static random /
//! resolvable / non-resolvable), the order the AD structures appear in, and
//! every repeat of every advertisement. Only the HCI layer exposes that, so
//! this module drives the controller directly.
//!
//! Reference: Bluetooth Core Specification v5.3, Vol 4 Part E (HCI).

use std::io;
use std::os::unix::io::RawFd;

use anyhow::{Context, Result};

const AF_BLUETOOTH: libc::c_int = 31;
const BTPROTO_HCI: libc::c_int = 1;
const SOL_HCI: libc::c_int = 0;
const HCI_FILTER: libc::c_int = 2;
const HCI_CHANNEL_RAW: u16 = 0;

const HCI_COMMAND_PKT: u8 = 0x01;
pub const HCI_EVENT_PKT: u8 = 0x04;

pub const EVT_CMD_COMPLETE: u8 = 0x0e;
pub const EVT_CMD_STATUS: u8 = 0x0f;
pub const EVT_LE_META: u8 = 0x3e;

pub const SUBEVT_LE_ADVERTISING_REPORT: u8 = 0x02;
pub const SUBEVT_LE_EXT_ADVERTISING_REPORT: u8 = 0x0d;

const OGF_LE_CTL: u16 = 0x08;
const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000b;
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000c;

fn opcode(ogf: u16, ocf: u16) -> u16 {
    (ogf << 10) | ocf
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrHci {
    hci_family: libc::sa_family_t,
    hci_dev: u16,
    hci_channel: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct HciFilter {
    type_mask: u32,
    event_mask: [u32; 2],
    opcode: u16,
}

impl HciFilter {
    fn set_packet_type(&mut self, t: u8) {
        self.type_mask |= 1 << (t & 31);
    }

    fn set_event(&mut self, e: u8) {
        let bit = (e & 63) as usize;
        self.event_mask[bit >> 5] |= 1 << (bit & 31);
    }
}

/// An open HCI socket bound to one controller.
pub struct HciSocket {
    fd: RawFd,
    dev: u16,
}

impl HciSocket {
    /// Open and bind to `hci<dev>`, filtering down to the events capture uses.
    pub fn open(dev: u16) -> Result<HciSocket> {
        // SAFETY: plain socket(2) with constant arguments.
        let fd = unsafe {
            libc::socket(
                AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                BTPROTO_HCI,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("opening AF_BLUETOOTH socket (needs root or CAP_NET_RAW)");
        }
        let sock = HciSocket { fd, dev };

        let mut filter = HciFilter::default();
        filter.set_packet_type(HCI_EVENT_PKT);
        filter.set_event(EVT_LE_META);
        filter.set_event(EVT_CMD_COMPLETE);
        filter.set_event(EVT_CMD_STATUS);
        // SAFETY: `filter` is a live, correctly sized repr(C) struct.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                SOL_HCI,
                HCI_FILTER,
                &filter as *const _ as *const libc::c_void,
                std::mem::size_of::<HciFilter>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("installing HCI event filter");
        }

        let addr = SockAddrHci {
            hci_family: AF_BLUETOOTH as libc::sa_family_t,
            hci_dev: dev,
            hci_channel: HCI_CHANNEL_RAW,
        };
        // SAFETY: `addr` is a live, correctly sized sockaddr for AF_BLUETOOTH.
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockAddrHci>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).with_context(|| {
                format!("binding to hci{dev} - is the adapter present and up? (`hciconfig hci{dev} up`)")
            });
        }

        sock.set_read_timeout_ms(250)?;
        Ok(sock)
    }

    pub fn device(&self) -> u16 {
        self.dev
    }

    fn set_read_timeout_ms(&self, ms: i64) -> Result<()> {
        let tv = libc::timeval {
            tv_sec: ms / 1000,
            tv_usec: (ms % 1000) * 1000,
        };
        // SAFETY: `tv` is a live, correctly sized timeval.
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("setting socket read timeout");
        }
        Ok(())
    }

    fn send_command(&self, ogf: u16, ocf: u16, params: &[u8]) -> Result<()> {
        let op = opcode(ogf, ocf);
        let mut pkt = Vec::with_capacity(4 + params.len());
        pkt.push(HCI_COMMAND_PKT);
        pkt.extend_from_slice(&op.to_le_bytes());
        pkt.push(params.len() as u8);
        pkt.extend_from_slice(params);

        // SAFETY: writing `pkt.len()` bytes from a buffer of exactly that size.
        let n = unsafe { libc::write(self.fd, pkt.as_ptr() as *const libc::c_void, pkt.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("sending HCI command {op:#06x}"));
        }
        Ok(())
    }

    /// Configure passive scanning.
    ///
    /// Passive means the controller listens but never transmits a scan
    /// request, so scanning puts nothing on the air.
    pub fn set_scan_parameters(&self, interval: u16, window: u16) -> Result<()> {
        let mut p = Vec::with_capacity(7);
        p.push(0x00); // 0x00 = passive scanning
        p.extend_from_slice(&interval.to_le_bytes());
        p.extend_from_slice(&window.to_le_bytes());
        p.push(0x00); // own address type: public
        p.push(0x00); // accept all advertisements
        self.send_command(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, &p)
    }

    pub fn set_scan_enable(&self, enable: bool, filter_duplicates: bool) -> Result<()> {
        self.send_command(
            OGF_LE_CTL,
            OCF_LE_SET_SCAN_ENABLE,
            &[enable as u8, filter_duplicates as u8],
        )
    }

    /// Read one HCI packet. `Ok(None)` means the read timed out, which is the
    /// normal way this returns when the air is quiet.
    pub fn read_packet(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        // SAFETY: writing at most `buf.len()` bytes into `buf`.
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            return match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => {
                    Ok(None)
                }
                _ => Err(err).context("reading from HCI socket"),
            };
        }
        Ok(Some(n as usize))
    }
}

impl Drop for HciSocket {
    fn drop(&mut self) {
        // Leaving the controller scanning would keep the radio busy for whoever
        // uses it next, so stop on the way out. Errors here are not actionable.
        let _ = self.set_scan_enable(false, false);
        // SAFETY: `fd` is owned by this struct and not used again.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcodes_match_the_specification() {
        assert_eq!(opcode(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS), 0x200b);
        assert_eq!(opcode(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE), 0x200c);
    }

    #[test]
    fn filter_bits_land_where_bluez_puts_them() {
        let mut f = HciFilter::default();
        f.set_packet_type(HCI_EVENT_PKT);
        assert_eq!(f.type_mask, 1 << 4);

        f.set_event(EVT_LE_META); // 0x3e = 62 -> word 1, bit 30
        assert_eq!(f.event_mask[1], 1 << 30);
        f.set_event(EVT_CMD_COMPLETE); // 0x0e = 14 -> word 0, bit 14
        assert_eq!(f.event_mask[0], 1 << 14);
    }

    #[test]
    fn structs_have_the_layout_the_kernel_expects() {
        assert_eq!(std::mem::size_of::<SockAddrHci>(), 6);
        assert_eq!(std::mem::size_of::<HciFilter>(), 16);
    }
}
