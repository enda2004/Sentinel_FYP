//! Capture backends.
//!
//! Each backend turns raw radio traffic into [`sentinel_core::Observation`]s
//! and pushes them down an mpsc channel. Backends keep only what capture
//! itself needs, such as counters: they do no identity resolution and make
//! no presence decisions. Identity is derived in `sentinel-core`, where it
//! can be tested without a radio, and presence is left to the engine that is
//! to consume these observations.
//!
//! * [`wifi`] - libpcap on a monitor-mode interface, with channel hopping
//! * [`ble`] - raw HCI passive scanning
//! * [`replay`] - pcap files, for development

pub mod ble;
pub mod dot11;
pub mod hci;
pub mod radiotap;
pub mod replay;
pub mod wifi;

pub use ble::BleStats;
pub use wifi::WifiStats;
