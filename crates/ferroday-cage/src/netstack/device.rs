//! The smoltcp device over the tap descriptor.
//!
//! The pump owns the reading: it pulls frames off the tap in batches,
//! inspects each one, and queues them here, so a frame can be examined —
//! and a listening socket created for it — before the interface processes
//! it. [`TapDevice`] merely pops that queue for the interface's receive
//! path and writes transmitted frames straight to the tap.

use std::collections::VecDeque;
use std::os::fd::OwnedFd;

use rustix::io::Errno;
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// The Ethernet header in front of every frame on a tap device.
const ETHERNET_HEADER: usize = 14;

/// A queue-backed smoltcp device over a nonblocking tap descriptor.
pub(super) struct TapDevice {
    /// The tap descriptor, created inside the sandbox's namespace. Holding
    /// it open pins the device and, transitively, the namespace.
    tap: OwnedFd,
    /// The interface MTU: the largest IP packet either side may carry.
    mtu: usize,
    /// Frames read from the tap and not yet consumed by the interface.
    ///
    /// Bounded by the pump's discipline rather than by a cap here: the pump
    /// fills the queue with at most `READ_BATCH` frames and then has the
    /// interface poll, which drains it in full before the next batch. A
    /// refactor that stopped polling between batches would make this unbounded.
    queue: VecDeque<Vec<u8>>,
    /// Frame buffers the interface has finished with, kept for reuse.
    ///
    /// Every received frame is a heap buffer, and the pump is on the data path
    /// for every packet the sandbox sends or receives, so the buffers circulate
    /// instead of being allocated and freed per frame. The population is
    /// self-limiting for the same reason the queue is: a buffer enters
    /// circulation only when [`take_buffer`](Self::take_buffer) finds this list
    /// empty, and each batch returns what it took.
    free: Vec<Vec<u8>>,
    /// The frame each transmission is assembled in before it goes to the tap.
    ///
    /// One buffer rather than a list: the borrow rules hand out at most one
    /// transmit token at a time, and it is consumed before the next is asked
    /// for. Transmission is as hot a path as reception, so it recycles for the
    /// same reason.
    tx_buf: Vec<u8>,
}

impl TapDevice {
    pub(super) fn new(tap: OwnedFd, mtu: u16) -> TapDevice {
        TapDevice {
            tap,
            mtu: usize::from(mtu),
            queue: VecDeque::new(),
            free: Vec::new(),
            tx_buf: Vec::new(),
        }
    }

    /// The tap descriptor, for the pump's poll set.
    pub(super) fn tap(&self) -> &OwnedFd {
        &self.tap
    }

    /// Reads one frame from the tap into `buf`. The tap is a packet
    /// descriptor: each successful read is exactly one frame.
    pub(super) fn read_frame(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        rustix::io::read(&self.tap, buf)
    }

    /// An empty frame buffer to fill and [`enqueue`](Self::enqueue): a recycled
    /// one where the interface has returned it, a fresh one otherwise.
    pub(super) fn take_buffer(&mut self) -> Vec<u8> {
        self.free
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.frame_capacity()))
    }

    /// Queues a frame for the interface's receive path.
    pub(super) fn enqueue(&mut self, frame: Vec<u8>) {
        self.queue.push_back(frame);
    }

    /// The size every read buffer needs: the MTU plus the Ethernet header.
    pub(super) fn frame_capacity(&self) -> usize {
        self.mtu + ETHERNET_HEADER
    }
}

impl phy::Device for TapDevice {
    type RxToken<'a> = QueueRxToken<'a>;
    type TxToken<'a> = TapTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // The receive token borrows the free list, the transmit token the
        // descriptor and the transmit frame: disjoint fields, so both can be
        // handed out at once.
        let TapDevice {
            tap,
            queue,
            free,
            tx_buf,
            ..
        } = self;
        let frame = queue.pop_front()?;
        Some((
            QueueRxToken { frame, free },
            TapTxToken { tap, frame: tx_buf },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let TapDevice { tap, tx_buf, .. } = self;
        Some(TapTxToken { tap, frame: tx_buf })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = self.frame_capacity();
        caps
    }
}

/// A received frame, handed to the interface by value, with the device's free
/// list to return its buffer to.
pub(super) struct QueueRxToken<'a> {
    frame: Vec<u8>,
    free: &'a mut Vec<Vec<u8>>,
}

impl phy::RxToken for QueueRxToken<'_> {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let result = f(&self.frame);
        // The interface is done with the frame. Empty the buffer, keeping its
        // capacity, and hand it back for the next read.
        self.frame.clear();
        self.free.push(std::mem::take(&mut self.frame));
        result
    }
}

/// A transmit slot: the closure builds the frame in the device's reusable
/// buffer and the token writes it to the tap.
pub(super) struct TapTxToken<'a> {
    tap: &'a OwnedFd,
    frame: &'a mut Vec<u8>,
}

impl phy::TxToken for TapTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // The buffer is the device's, kept across transmissions; clearing
        // before the resize means the resize zeroes rather than preserving a
        // previous frame's bytes.
        let frame = self.frame;
        frame.clear();
        frame.resize(len, 0);
        let result = f(&mut frame[..]);
        // A tap write takes the whole frame or nothing. Failure — the
        // injection queue is momentarily full, or the device is going away
        // — drops the frame, which is what a network does; the protocols
        // above recover, and a vanished device surfaces through the pump's
        // read path.
        let _ = rustix::io::write(self.tap, frame);
        result
    }
}
