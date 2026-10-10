// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Connection builder: the core's `Config` plus async limits.
// The fields are read by the driver, which lands in a later task.
#![allow(dead_code)]

use h3wire::{Config, UsageError};

/// Configures a client or server connection.
#[derive(Clone, Debug)]
pub struct Builder {
    config: Config,
    pub(crate) read_ahead: usize,
    pub(crate) read_ahead_cap: usize,
    pub(crate) demand_chunk: usize,
    pub(crate) send_capacity: usize,
    pub(crate) work_budget: usize,
    pub(crate) datagram_queue: usize,
    pub(crate) pending_dgrams_stream: (usize, usize),
    pub(crate) pending_dgrams_conn: (usize, usize),
}

impl Default for Builder {
    fn default() -> Self {
        Builder {
            config: Config::default(),
            read_ahead: 64 * 1024,
            read_ahead_cap: 1024 * 1024,
            demand_chunk: 16 * 1024,
            send_capacity: 64 * 1024,
            work_budget: 64,
            datagram_queue: 64,
            pending_dgrams_stream: (16, 16 * 1024),
            pending_dgrams_conn: (256, 256 * 1024),
        }
    }
}

impl Builder {
    /// A builder with the default limits.
    pub fn new() -> Self {
        Self::default()
    }

    /// Server: advertise and accept Extended CONNECT (RFC 9220).
    pub fn enable_connect_protocol(&mut self, on: bool) -> &mut Self {
        self.config.enable_connect_protocol = on;
        self
    }

    /// Advertise an extra setting; same validation as [`h3wire::Config::add_setting`].
    pub fn add_setting(&mut self, id: u64, value: u64) -> Result<&mut Self, UsageError> {
        self.config.add_setting(id, value)?;
        Ok(self)
    }

    /// Send a reserved (GREASE) setting and frame on the control stream.
    pub fn grease(&mut self, on: bool) -> &mut Self {
        self.config.grease = on;
        self
    }

    /// The largest encoded field section buffered (the real allocation bound; not
    /// advertised). Default 65,536.
    pub fn max_encoded_field_section_size(&mut self, n: usize) -> &mut Self {
        self.config.max_encoded_field_section_size = n;
        self
    }

    /// Advertised as `SETTINGS_MAX_FIELD_SECTION_SIZE` when `Some`; advertised only, not
    /// enforced.
    pub fn max_field_section_size(&mut self, n: Option<u64>) -> &mut Self {
        self.config.max_field_section_size = n;
        self
    }

    /// Per-stream body read-ahead without application demand. Default 64 KiB.
    pub fn read_ahead(&mut self, n: usize) -> &mut Self {
        self.read_ahead = n;
        self
    }

    /// Per-connection cap on speculative read-ahead. Default 1 MiB.
    pub fn read_ahead_cap(&mut self, n: usize) -> &mut Self {
        self.read_ahead_cap = n;
        self
    }

    /// Bytes read per demand reservation. Default 16 KiB.
    pub fn demand_chunk(&mut self, n: usize) -> &mut Self {
        self.demand_chunk = n;
        self
    }

    /// Per-stream send-queue capacity. Default 64 KiB.
    pub fn send_capacity(&mut self, n: usize) -> &mut Self {
        self.send_capacity = n;
        self
    }

    /// Operations per driver pass before it yields. Default 64.
    pub fn work_budget(&mut self, n: usize) -> &mut Self {
        self.work_budget = n;
        self
    }

    /// Capacity of a registered datagram queue, and of the connection's queue of datagrams
    /// waiting for the driver to send them (both drop-oldest). Default 64.
    pub fn datagram_queue(&mut self, n: usize) -> &mut Self {
        self.datagram_queue = n;
        self
    }

    /// Pending (not yet registered) datagrams kept per stream: count and bytes. Default
    /// 16 datagrams / 16 KiB.
    pub fn pending_datagrams_per_stream(&mut self, count: usize, bytes: usize) -> &mut Self {
        self.pending_dgrams_stream = (count, bytes);
        self
    }

    /// Pending datagrams kept per connection: count and bytes. Default 256 / 256 KiB.
    pub fn pending_datagrams_per_conn(&mut self, count: usize, bytes: usize) -> &mut Self {
        self.pending_dgrams_conn = (count, bytes);
        self
    }

    /// The core config; `h3_datagram` is set iff the transport has datagrams.
    pub(crate) fn core_config(&self, datagrams_available: bool) -> Config {
        let mut c = self.config.clone();
        c.h3_datagram = datagrams_available;
        c
    }
}
