//! Passive Bluetooth LE advertisement capture.
//!
//! Bluetooth LE reaches people who never join the Wi-Fi: phones, watches and
//! earbuds advertise continuously whether or not they are paired with
//! anything nearby. Modern devices use resolvable private addresses that
//! rotate every fifteen minutes or so, which is why the advertisement
//! *payload* rather than the address carries the identity.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use sentinel_core::config::BleConfig;
use sentinel_core::fingerprint::{BleEvidence, Evidence};
use sentinel_core::mac::{MacAddr, MacKind};
use sentinel_core::observation::Observation;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use crate::hci::{
    HciSocket, EVT_LE_META, HCI_EVENT_PKT, SUBEVT_LE_ADVERTISING_REPORT,
    SUBEVT_LE_EXT_ADVERTISING_REPORT,
};

#[derive(Debug, Default)]
pub struct BleStats {
    /// LE events read from the controller. Each normally carries one
    /// advertising report.
    pub reports: AtomicU64,
    /// Advertising reports decoded into observations.
    pub parsed: AtomicU64,
    /// Times the watchdog switched the scan back on after a silence.
    pub rescans: AtomicU64,
}

/// What [`ScanWatchdog::check`] wants done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogAction {
    Nothing,
    /// Silent for the whole window: switch the scan back on. `first` is true
    /// for the first time in this silence, so the log says so once rather than
    /// once a minute for a whole empty weekday.
    Reenable { first: bool },
}

/// Switches the scan back on in case it was switched off from outside.
///
/// The controller has one scan state, shared by every program on the host.
/// Any of them can send LE Set Scan Enable = 0 - another capture program
/// stopping, for example - and nothing tells this process: advertisements
/// just stop.
///
/// A scan switched off looks exactly like a quiet house, and silence is never
/// treated as a fault, since a house can be quiet for hours. The scan is
/// switched back on after every window of silence for as long as it lasts,
/// which is harmless if it was still on. Apart from shutdown or a closed
/// channel, capture stops only on a socket error: a command that cannot be
/// sent to the controller, or a read that fails.
#[derive(Debug)]
pub struct ScanWatchdog {
    /// `None`: the watchdog is off.
    silence: Option<Duration>,
    last_heard: Instant,
    reenabled: bool,
}

impl ScanWatchdog {
    pub fn new(silence_secs: u64, now: Instant) -> ScanWatchdog {
        ScanWatchdog {
            silence: (silence_secs > 0).then(|| Duration::from_secs(silence_secs)),
            last_heard: now,
            reenabled: false,
        }
    }

    /// An advertisement arrived. Returns true if it is the first since the
    /// scan was re-enabled, i.e. the silence is over.
    pub fn heard(&mut self, now: Instant) -> bool {
        self.last_heard = now;
        std::mem::take(&mut self.reenabled)
    }

    pub fn check(&mut self, now: Instant) -> WatchdogAction {
        let Some(limit) = self.silence else {
            return WatchdogAction::Nothing;
        };
        if now.duration_since(self.last_heard) < limit {
            return WatchdogAction::Nothing;
        }
        // The re-enabled scan gets a whole window of its own.
        let first = !std::mem::replace(&mut self.reenabled, true);
        self.last_heard = now;
        WatchdogAction::Reenable { first }
    }
}

/// Passive scan with this program's parameters. Scanning may already be
/// enabled - by bluetoothd, by another program, or still by this one - and the
/// controller rejects a parameter change while it is, so always stop first.
fn start_scan(sock: &HciSocket, cfg: &BleConfig) -> Result<()> {
    sock.set_scan_enable(false, false)?;
    sock.set_scan_parameters(cfg.scan_interval, cfg.scan_window)?;
    sock.set_scan_enable(true, cfg.filter_duplicates)
}

/// One decoded advertising report.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvReport {
    pub address: MacAddr,
    pub address_type: u8,
    pub rssi: Option<i8>,
    pub evidence: BleEvidence,
}

/// Start scanning. Blocks until `shutdown` is set.
pub fn run(
    cfg: BleConfig,
    tx: Sender<Observation>,
    shutdown: Arc<AtomicBool>,
    stats: Arc<BleStats>,
) -> Result<()> {
    let sock = HciSocket::open(cfg.adapter).context("opening HCI socket")?;
    start_scan(&sock, &cfg)?;

    info!(
        adapter = format!("hci{}", sock.device()),
        interval_ms = cfg.scan_interval as f64 * 0.625,
        window_ms = cfg.scan_window as f64 * 0.625,
        "BLE passive scan running"
    );

    let mut watchdog = ScanWatchdog::new(cfg.scan_silence_secs, Instant::now());
    let mut buf = [0u8; 512];
    'scan: while !shutdown.load(Ordering::Relaxed) {
        // A read times out every 250 ms when the air is quiet, so this runs
        // even when nothing at all is arriving.
        match watchdog.check(Instant::now()) {
            WatchdogAction::Nothing => {}
            WatchdogAction::Reenable { first } => {
                stats.rescans.fetch_add(1, Ordering::Relaxed);
                if first {
                    info!(
                        silence_secs = cfg.scan_silence_secs,
                        "no Bluetooth advertisement for {} s; either the house is quiet or \
                         another program switched the scan off - switching it back on, and \
                         repeating until one arrives",
                        cfg.scan_silence_secs
                    );
                } else {
                    debug!("still no Bluetooth advertisement; switching the scan back on again");
                }
                start_scan(&sock, &cfg).context("re-enabling the BLE scan")?;
            }
        }

        let Some(n) = sock.read_packet(&mut buf)? else {
            continue;
        };
        if n == 0 {
            continue;
        }
        // Command replies are read too; only LE events count.
        if n >= 2 && buf[1] == EVT_LE_META {
            stats.reports.fetch_add(1, Ordering::Relaxed);
        }
        let reports = parse_event(&buf[..n]);
        if !reports.is_empty() && watchdog.heard(Instant::now()) {
            info!("Bluetooth advertisements resumed");
        }
        for report in reports {
            stats.parsed.fetch_add(1, Ordering::Relaxed);
            let obs = Observation {
                ts: Utc::now(),
                mac: report.address,
                mac_kind: MacKind::classify_ble(&report.address, report.address_type),
                rssi: report.rssi,
                evidence: Evidence::Ble(report.evidence),
            };
            match tx.try_send(obs) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    debug!("observation channel full; dropping a BLE sighting")
                }
                Err(TrySendError::Closed(_)) => {
                    info!("observation receiver closed");
                    break 'scan;
                }
            }
        }
    }

    if let Err(e) = sock.set_scan_enable(false, false) {
        warn!("could not stop scanning cleanly: {e}");
    }
    info!("BLE scan stopped");
    Ok(())
}

/// Decode an HCI event packet into zero or more advertising reports.
pub fn parse_event(pkt: &[u8]) -> Vec<AdvReport> {
    // [packet type][event code][parameter length][parameters...]
    if pkt.len() < 4 || pkt[0] != HCI_EVENT_PKT || pkt[1] != EVT_LE_META {
        return Vec::new();
    }
    let plen = pkt[2] as usize;
    let Some(params) = pkt.get(3..3 + plen) else {
        return Vec::new();
    };
    if params.is_empty() {
        return Vec::new();
    }
    match params[0] {
        SUBEVT_LE_ADVERTISING_REPORT => parse_legacy_reports(&params[1..]),
        SUBEVT_LE_EXT_ADVERTISING_REPORT => parse_extended_reports(&params[1..]),
        _ => Vec::new(),
    }
}

/// LE Advertising Report (Core Spec Vol 4, Part E, 7.7.65.2).
///
/// The specification describes the parameters as parallel arrays. This reads
/// each report's fields consecutively instead, as BlueZ does; the two layouts
/// are the same for an event holding a single report.
fn parse_legacy_reports(mut body: &[u8]) -> Vec<AdvReport> {
    if body.is_empty() {
        return Vec::new();
    }
    let num = body[0] as usize;
    body = &body[1..];
    let mut out = Vec::with_capacity(num);

    for _ in 0..num {
        if body.len() < 9 {
            break;
        }
        let event_type = body[0];
        let address_type = body[1];
        let Some(address) = MacAddr::from_slice(&body[2..8]) else {
            break;
        };
        let data_len = body[8] as usize;
        if body.len() < 9 + data_len + 1 {
            break;
        }
        let data = &body[9..9 + data_len];
        let rssi = body[9 + data_len] as i8;

        let mut evidence = parse_ad_structures(data);
        // 0x04 = SCAN_RSP: a reply to somebody else's active scan. Worth
        // recording (it often carries the device name) but flagged, because its
        // payload differs from the device's own advertisement.
        evidence.scan_response = event_type == 0x04;

        out.push(AdvReport {
            address,
            address_type,
            // 127 is the "RSSI not available" sentinel.
            rssi: if rssi == 127 { None } else { Some(rssi) },
            evidence,
        });
        body = &body[9 + data_len + 1..];
    }
    out
}

/// LE Extended Advertising Report (Core Spec Vol 4, Part E, 7.7.65.13),
/// emitted by 5.0 controllers when extended scanning is in use.
fn parse_extended_reports(mut body: &[u8]) -> Vec<AdvReport> {
    if body.is_empty() {
        return Vec::new();
    }
    let num = body[0] as usize;
    body = &body[1..];
    let mut out = Vec::with_capacity(num);

    const HEADER: usize = 24;
    for _ in 0..num {
        if body.len() < HEADER {
            break;
        }
        let event_type = u16::from_le_bytes([body[0], body[1]]);
        let address_type = body[2];
        let Some(address) = MacAddr::from_slice(&body[3..9]) else {
            break;
        };
        // Event_Type(2) Address_Type(1) Address(6) Primary_PHY(1) Secondary_PHY(1)
        // Advertising_SID(1) TX_Power(1) RSSI(1) ...
        let tx_power = body[12] as i8;
        let rssi = body[13] as i8;
        let data_len = body[23] as usize;
        if body.len() < HEADER + data_len {
            break;
        }
        let data = &body[HEADER..HEADER + data_len];

        let mut evidence = parse_ad_structures(data);
        evidence.scan_response = event_type & 0x0008 != 0;
        if evidence.tx_power.is_none() && tx_power != 127 {
            evidence.tx_power = Some(tx_power);
        }

        out.push(AdvReport {
            address,
            address_type,
            rssi: if rssi == 127 { None } else { Some(rssi) },
            evidence,
        });
        body = &body[HEADER + data_len..];
    }
    out
}

// AD types, from the Bluetooth assigned numbers.
const AD_FLAGS: u8 = 0x01;
const AD_UUID16_PARTIAL: u8 = 0x02;
const AD_UUID16_COMPLETE: u8 = 0x03;
const AD_UUID32_PARTIAL: u8 = 0x04;
const AD_UUID32_COMPLETE: u8 = 0x05;
const AD_UUID128_PARTIAL: u8 = 0x06;
const AD_UUID128_COMPLETE: u8 = 0x07;
const AD_NAME_SHORT: u8 = 0x08;
const AD_NAME_COMPLETE: u8 = 0x09;
const AD_TX_POWER: u8 = 0x0a;
const AD_SERVICE_DATA_16: u8 = 0x16;
const AD_MANUFACTURER: u8 = 0xff;

/// Walk the AD structures in an advertising payload.
pub fn parse_ad_structures(data: &[u8]) -> BleEvidence {
    let mut ev = BleEvidence::default();
    let mut i = 0usize;

    while i < data.len() {
        let len = data[i] as usize;
        // A zero length is the padding that marks the end of the payload.
        if len == 0 {
            break;
        }
        if i + 1 + len > data.len() {
            break; // truncated structure
        }
        let ad_type = data[i + 1];
        let payload = &data[i + 2..i + 1 + len];
        ev.ad_order.push(ad_type);

        match ad_type {
            AD_FLAGS => ev.flags = payload.first().copied(),
            AD_UUID16_PARTIAL | AD_UUID16_COMPLETE => {
                for c in payload.chunks_exact(2) {
                    ev.service_uuids
                        .push(format!("{:04x}", u16::from_le_bytes([c[0], c[1]])));
                }
            }
            AD_UUID32_PARTIAL | AD_UUID32_COMPLETE => {
                for c in payload.chunks_exact(4) {
                    ev.service_uuids.push(format!(
                        "{:08x}",
                        u32::from_le_bytes([c[0], c[1], c[2], c[3]])
                    ));
                }
            }
            AD_UUID128_PARTIAL | AD_UUID128_COMPLETE => {
                for c in payload.chunks_exact(16) {
                    ev.service_uuids.push(format_uuid128(c));
                }
            }
            AD_NAME_SHORT | AD_NAME_COMPLETE => {
                let name = String::from_utf8_lossy(payload).trim().to_string();
                if !name.is_empty() {
                    ev.local_name = Some(name);
                }
            }
            AD_TX_POWER => ev.tx_power = payload.first().map(|b| *b as i8),
            AD_SERVICE_DATA_16 => {
                if payload.len() >= 2 {
                    ev.service_uuids.push(format!(
                        "{:04x}",
                        u16::from_le_bytes([payload[0], payload[1]])
                    ));
                }
            }
            AD_MANUFACTURER => {
                if payload.len() >= 2 {
                    ev.company_id = Some(u16::from_le_bytes([payload[0], payload[1]]));
                    // Only the leading bytes are kept. For Apple these are the
                    // Continuity message type and length, which distinguish a
                    // phone from a watch from earbuds; the remainder is a
                    // rotating token and would poison the fingerprint.
                    let rest = &payload[2..];
                    ev.mfg_prefix = rest[..rest.len().min(2)].to_vec();
                    ev.mfg_len = rest.len();
                }
            }
            _ => {}
        }
        i += 1 + len;
    }
    ev
}

fn format_uuid128(b: &[u8]) -> String {
    // 128-bit UUIDs are transmitted little-endian.
    let mut r = b.to_vec();
    r.reverse();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------ watchdog

    /// Advertisements stop at t=0 because something switched the scan off,
    /// and the window is 60 s. Nothing happens until a whole window has
    /// passed; then the scan is switched back on, and again each window
    /// after that for as long as the silence lasts.
    #[test]
    fn a_silent_scan_is_switched_back_on_every_window() {
        let t0 = Instant::now();
        let s = |n: u64| t0 + Duration::from_secs(n);
        let mut w = ScanWatchdog::new(60, t0);

        assert_eq!(w.check(s(59)), WatchdogAction::Nothing);
        assert_eq!(w.check(s(60)), WatchdogAction::Reenable { first: true });
        // The re-enabled scan gets its own full window, counted from then.
        assert_eq!(w.check(s(90)), WatchdogAction::Nothing);
        assert_eq!(w.check(s(119)), WatchdogAction::Nothing);
        assert_eq!(w.check(s(120)), WatchdogAction::Reenable { first: false });
    }

    /// Nine hours with nothing on the air: the watchdog re-enables once a
    /// minute, and that is all it does.
    #[test]
    fn re_enables_once_a_minute_through_a_long_silence() {
        let t0 = Instant::now();
        let mut w = ScanWatchdog::new(60, t0);

        let actions: Vec<WatchdogAction> = (1..=9 * 3600)
            .map(|n| w.check(t0 + Duration::from_secs(n)))
            .filter(|a| *a != WatchdogAction::Nothing)
            .collect();

        assert_eq!(actions.len(), 9 * 60, "one per minute for nine hours");
        assert_eq!(actions[0], WatchdogAction::Reenable { first: true });
        assert!(
            actions[1..].iter().all(|a| *a == WatchdogAction::Reenable { first: false }),
            "only the first of a silence is reported as the first"
        );
    }

    /// The next advertisement ends the silence (and says so, once), and the
    /// watchdog is back to normal: the next silence counts as a new one.
    #[test]
    fn an_advertisement_after_re_enabling_resets_the_watchdog() {
        let t0 = Instant::now();
        let s = |n: u64| t0 + Duration::from_secs(n);
        let mut w = ScanWatchdog::new(60, t0);

        assert!(!w.heard(s(10)), "an ordinary advertisement is not a recovery");
        assert_eq!(w.check(s(69)), WatchdogAction::Nothing, "the window restarts at each one");
        assert_eq!(w.check(s(70)), WatchdogAction::Reenable { first: true });
        assert!(w.heard(s(71)), "the first advertisement after re-enabling is the recovery");
        assert!(!w.heard(s(72)), "and only the first");
        assert_eq!(
            w.check(s(132)),
            WatchdogAction::Reenable { first: true },
            "a fresh silence starts over"
        );
    }

    #[test]
    fn a_zero_window_turns_the_watchdog_off() {
        let t0 = Instant::now();
        let mut w = ScanWatchdog::new(0, t0);
        assert_eq!(w.check(t0 + Duration::from_secs(86_400)), WatchdogAction::Nothing);
    }

    fn ad(t: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![(payload.len() + 1) as u8, t];
        v.extend_from_slice(payload);
        v
    }

    /// Wrap advertising data in a complete HCI LE Advertising Report event.
    fn event(addr_type: u8, addr: [u8; 6], data: &[u8], rssi: i8) -> Vec<u8> {
        let mut params = vec![SUBEVT_LE_ADVERTISING_REPORT, 0x01, 0x00, addr_type];
        params.extend_from_slice(&addr);
        params.push(data.len() as u8);
        params.extend_from_slice(data);
        params.push(rssi as u8);

        let mut pkt = vec![HCI_EVENT_PKT, EVT_LE_META, params.len() as u8];
        pkt.extend_from_slice(&params);
        pkt
    }

    #[test]
    fn decodes_a_typical_apple_advertisement() {
        let mut data = ad(AD_FLAGS, &[0x1a]);
        data.extend(ad(AD_MANUFACTURER, &[0x4c, 0x00, 0x10, 0x05, 0x1b, 0x11, 0x22, 0x33]));

        let reports = parse_event(&event(1, [0x40, 1, 2, 3, 4, 5], &data, -55));
        assert_eq!(reports.len(), 1);
        let r = &reports[0];
        assert_eq!(r.address.to_string(), "40:01:02:03:04:05");
        assert_eq!(r.rssi, Some(-55));
        assert_eq!(r.evidence.company_id, Some(0x004c));
        assert_eq!(r.evidence.vendor_name(), Some("Apple"));
        assert_eq!(r.evidence.mfg_prefix, vec![0x10, 0x05]);
        assert_eq!(r.evidence.ad_order, vec![AD_FLAGS, AD_MANUFACTURER]);
        assert_eq!(r.evidence.flags, Some(0x1a));

        // A resolvable private address must be classified as such.
        assert_eq!(
            MacKind::classify_ble(&r.address, r.address_type),
            MacKind::BleResolvablePrivate
        );
    }

    #[test]
    fn rotating_payload_tail_does_not_change_the_signature() {
        // Same device, two Continuity broadcasts whose trailing token differs.
        let mut a = ad(AD_FLAGS, &[0x1a]);
        a.extend(ad(AD_MANUFACTURER, &[0x4c, 0x00, 0x10, 0x05, 0xaa, 0xbb, 0xcc, 0xdd]));
        let mut b = ad(AD_FLAGS, &[0x1a]);
        b.extend(ad(AD_MANUFACTURER, &[0x4c, 0x00, 0x10, 0x05, 0x11, 0x22, 0x33, 0x44]));

        let sa = parse_ad_structures(&a).signature();
        let sb = parse_ad_structures(&b).signature();
        assert_eq!(sa, sb, "only the stable prefix should feed the fingerprint");
    }

    #[test]
    fn different_device_roles_get_different_signatures() {
        let mut phone = ad(AD_FLAGS, &[0x1a]);
        phone.extend(ad(AD_MANUFACTURER, &[0x4c, 0x00, 0x10, 0x05, 0x00]));
        let mut earbuds = ad(AD_FLAGS, &[0x1a]);
        earbuds.extend(ad(AD_MANUFACTURER, &[0x4c, 0x00, 0x07, 0x19, 0x00, 0x01, 0x02]));
        assert_ne!(
            parse_ad_structures(&phone).signature(),
            parse_ad_structures(&earbuds).signature()
        );
    }

    #[test]
    fn decodes_names_uuids_and_tx_power() {
        let mut data = ad(AD_NAME_COMPLETE, b"Sam's Watch");
        data.extend(ad(AD_UUID16_COMPLETE, &[0x0d, 0x18, 0x0f, 0x18])); // 180d, 180f
        data.extend(ad(AD_TX_POWER, &[(-12i8) as u8]));

        let ev = parse_ad_structures(&data);
        assert_eq!(ev.local_name.as_deref(), Some("Sam's Watch"));
        assert_eq!(ev.service_uuids, vec!["180d".to_string(), "180f".to_string()]);
        assert_eq!(ev.tx_power, Some(-12));
    }

    #[test]
    fn decodes_128_bit_uuids_in_wire_order() {
        let mut le = (0..16u8).collect::<Vec<u8>>();
        le.reverse(); // transmitted little-endian
        let ev = parse_ad_structures(&ad(AD_UUID128_COMPLETE, &le));
        assert_eq!(ev.service_uuids, vec!["00010203-0405-0607-0809-0a0b0c0d0e0f"]);
    }

    #[test]
    fn malformed_payloads_are_survivable() {
        // Length field overruns the buffer.
        assert!(parse_ad_structures(&[0x20, 0xff, 0x01]).ad_order.is_empty());
        // Zero-length terminator.
        assert!(parse_ad_structures(&[0x00, 0x00, 0x00]).ad_order.is_empty());
        // Truncated events.
        assert!(parse_event(&[]).is_empty());
        assert!(parse_event(&[HCI_EVENT_PKT, EVT_LE_META, 40, 0x02]).is_empty());
        // Wrong event code.
        assert!(parse_event(&[HCI_EVENT_PKT, 0x0e, 1, 0]).is_empty());
    }

    #[test]
    fn rssi_sentinel_is_reported_as_unknown() {
        let reports = parse_event(&event(0, [1, 2, 3, 4, 5, 6], &ad(AD_FLAGS, &[0x06]), 127));
        assert_eq!(reports[0].rssi, None);
    }

    #[test]
    fn decodes_extended_reports_from_bluetooth_5_controllers() {
        let data = ad(AD_MANUFACTURER, &[0x75, 0x00, 0x42, 0x43]);
        let mut params = vec![SUBEVT_LE_EXT_ADVERTISING_REPORT, 0x01];
        // Event type bits: 0 connectable, 1 scannable, 3 scan response, 4 legacy.
        params.extend_from_slice(&0x001bu16.to_le_bytes());
        params.push(0x01); // address type: random
        params.extend_from_slice(&[0xc0, 1, 2, 3, 4, 5]); // static random address
        params.extend_from_slice(&[0x01, 0x00, 0x00]); // primary/secondary phy, sid
        params.push((-20i8) as u8); // tx power
        params.push((-60i8) as u8); // rssi
        params.extend_from_slice(&[0x00, 0x00]); // periodic interval
        params.push(0x00); // direct address type
        params.extend_from_slice(&[0u8; 6]); // direct address
        params.push(data.len() as u8);
        params.extend_from_slice(&data);

        let mut pkt = vec![HCI_EVENT_PKT, EVT_LE_META, params.len() as u8];
        pkt.extend_from_slice(&params);

        let reports = parse_event(&pkt);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].rssi, Some(-60));
        assert_eq!(reports[0].evidence.company_id, Some(0x0075));
        assert_eq!(reports[0].evidence.tx_power, Some(-20));
        assert!(reports[0].evidence.scan_response);
        assert_eq!(
            MacKind::classify_ble(&reports[0].address, reports[0].address_type),
            MacKind::BleStaticRandom
        );
    }
}
