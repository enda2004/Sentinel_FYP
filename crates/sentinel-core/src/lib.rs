//! Core domain model for the passive Wi-Fi / BLE intruder alarm.
//!
//! This crate is deliberately free of any hardware, network or database
//! dependency: it is meant to work only on [`Observation`]s, knowing nothing
//! about how they were captured or where they are stored. That keeps
//! fingerprinting unit-testable on any machine, lets the capture layer be
//! swapped (live radio, pcap replay, synthetic data) without touching it, and
//! keeps a database driver out of anything that only captures.

pub mod mac;

pub use mac::{MacAddr, MacKind};
