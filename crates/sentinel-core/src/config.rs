//! Runtime configuration, loaded from TOML.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub wifi: WifiConfig,
    pub ble: BleConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WifiConfig {
    pub enabled: bool,
    /// Monitor-mode interface, e.g. `wlan1`. See `scripts/monitor-mode.sh`,
    /// which switches an adapter to monitor mode without renaming it.
    pub interface: String,
    /// Channels to hop between. 2.4 GHz 1/6/11 plus the common 5 GHz channels.
    pub channels: Vec<u16>,
    /// How long to sit on each channel. Probe requests are bursty, so dwelling
    /// too briefly misses whole bursts.
    pub dwell_ms: u64,
    /// Whether capture may retune the adapter itself. Turn off if something
    /// else (e.g. airodump-ng) is already hopping.
    pub hop: bool,
    /// Also track already-associated clients from data frames. These addresses
    /// are stable per network, which makes them a strong household signal.
    pub capture_data_frames: bool,
    /// Drop anything weaker than this - keeps neighbours out of the dataset.
    pub min_rssi: i8,
    /// Capture buffer size for libpcap, in bytes.
    pub buffer_bytes: i32,
}

impl Default for WifiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interface: "wlan1".to_string(),
            channels: vec![1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161],
            dwell_ms: 350,
            hop: true,
            capture_data_frames: true,
            min_rssi: -80,
            buffer_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BleConfig {
    pub enabled: bool,
    /// HCI device index: 0 means hci0.
    pub adapter: u16,
    /// Scan interval and window in 0.625 ms units. Equal values mean the radio
    /// listens continuously.
    pub scan_interval: u16,
    pub scan_window: u16,
    /// Ask the controller to suppress repeat advertisements. Off by default:
    /// repeats are what show dwell time and RSSI trends.
    pub filter_duplicates: bool,
    /// After this long with no advertisement at all, the scan is switched back
    /// on in case another program switched it off, and again after each further
    /// silence this long. 0 turns the watchdog off.
    pub scan_silence_secs: u64,
}

impl Default for BleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            adapter: 0,
            scan_interval: 0x0060, // 60 ms
            scan_window: 0x0060,
            filter_duplicates: false,
            scan_silence_secs: 60,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .with_context(|| format!("parsing config {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.wifi.enabled {
            anyhow::ensure!(!self.wifi.interface.is_empty(), "wifi.interface is required");
            anyhow::ensure!(!self.wifi.channels.is_empty(), "wifi.channels must not be empty");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every assertion below is of the form "the default config is valid, and
    /// this one change makes it invalid". Written that way so a new rule added
    /// to `validate` cannot make these pass for the wrong reason: if the
    /// default ever stops validating, the first test fails and says so.
    fn broken(f: impl FnOnce(&mut Config)) -> String {
        let mut cfg = Config::default();
        f(&mut cfg);
        match cfg.validate() {
            Ok(()) => panic!("validate accepted a configuration it should have refused"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn the_shipped_defaults_are_valid() {
        Config::default()
            .validate()
            .expect("the defaults must pass their own validator");
    }

    /// With an empty channel list there is nothing to hop between, and the
    /// radio would sit on whatever channel it was left on. An empty interface
    /// name gives capture nothing to open.
    #[test]
    fn wifi_needs_an_interface_and_at_least_one_channel_when_enabled() {
        assert!(broken(|c| c.wifi.interface = String::new()).contains("wifi.interface"));
        assert!(broken(|c| c.wifi.channels.clear()).contains("wifi.channels"));

        // …and neither is required when the radio is switched off, which is how
        // a BLE-only deployment is configured.
        let mut cfg = Config::default();
        cfg.wifi.enabled = false;
        cfg.wifi.interface = String::new();
        cfg.wifi.channels.clear();
        cfg.validate()
            .expect("a BLE-only deployment must not need a Wi-Fi interface");
    }
}
