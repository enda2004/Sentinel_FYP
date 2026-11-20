//! Capture backends.
//!
//! Backends are to turn raw radio traffic into observations. The parsers
//! they rely on work on byte slices alone, so they can be tested without a
//! radio.

pub mod dot11;
pub mod radiotap;
