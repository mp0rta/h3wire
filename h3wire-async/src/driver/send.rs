// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Writing: core-owned bytes (HEADERS, control and QPACK streams) and `poll_stopped`.
//! Task 5 adds DATA, FIN-only ends and acknowledgement tracking.

use super::Driver;
use crate::quic::{self, SendStream, TransportError, WriteError};
use crate::state::Dir;
use bytes::Bytes;
use h3wire::{H3Code, StreamId};
use std::task::{Context, Poll};

impl<C: quic::Connection> Driver<C> {
    /// Write every stream the core has bytes for, except those waiting on the transport.
    pub(super) fn write_sendable(&mut self, budget: &mut usize) -> Result<bool, TransportError> {
        let ids: Vec<StreamId> = self.shared.with(|i| i.conn.sendable().collect());
        let mut moved = false;
        for id in ids {
            if *budget == 0 {
                break;
            }
            if !self.write_blocked.contains(&id) {
                moved |= self.write_stream(id, budget)?;
            }
        }
        Ok(moved)
    }

    /// Offer the core's pending bytes until the transport takes less than offered.
    pub(super) fn write_stream(
        &mut self,
        id: StreamId,
        budget: &mut usize,
    ) -> Result<bool, TransportError> {
        let waker = self.shared.ready_waker(id, Dir::Send);
        let mut cx = Context::from_waker(&waker);
        let mut moved = false;
        while *budget > 0 {
            let Some(s) = self.sends.get_mut(&id) else {
                break;
            };
            let Some(bytes) = self
                .shared
                .with(|i| i.conn.poll_send(id).map(Bytes::copy_from_slice))
            else {
                break;
            };
            let offered = bytes.len();
            match s.poll_write_chunks(&mut cx, &mut [bytes]) {
                Poll::Pending => {
                    self.write_blocked.insert(id);
                    break;
                }
                Poll::Ready(Ok(w)) => {
                    *budget -= 1;
                    moved = true;
                    // An Err is a state notification only.
                    let _ = self.shared.with(|i| i.conn.sent(id, w.bytes));
                    if w.bytes < offered {
                        break;
                    }
                }
                Poll::Ready(Err(e)) => {
                    *budget -= 1;
                    self.write_failed(id, e)?;
                    return Ok(true);
                }
            }
        }
        Ok(moved)
    }

    /// Learn of a peer STOP_SENDING (or completion) on a send half we hold.
    pub(super) fn poll_stopped(
        &mut self,
        id: StreamId,
        budget: &mut usize,
    ) -> Result<bool, TransportError> {
        let Some(s) = self.sends.get_mut(&id) else {
            return Ok(false);
        };
        let waker = self.shared.ready_waker(id, Dir::Send);
        let Poll::Ready(r) = s.poll_stopped(&mut Context::from_waker(&waker)) else {
            return Ok(false);
        };
        *budget = budget.saturating_sub(1);
        match r? {
            Some(code) => self.stopped(id, code),
            // Completed and acknowledged; Task 5 records `acked`.
            None => {
                self.sends.remove(&id);
            }
        }
        Ok(true)
    }

    fn write_failed(&mut self, id: StreamId, e: WriteError) -> Result<(), TransportError> {
        match e {
            WriteError::Stopped(code) => self.stopped(id, code),
            WriteError::Transport(e) => return Err(e),
            WriteError::Closed => {
                self.sends.remove(&id);
            }
        }
        Ok(())
    }

    /// The peer sent STOP_SENDING: the core resets our half (or closes the connection
    /// for a critical stream) through actions.
    fn stopped(&mut self, id: StreamId, code: u64) {
        let _ = self
            .shared
            .with(|i| i.conn.stop_sending_received(id, H3Code(code)));
    }
}
