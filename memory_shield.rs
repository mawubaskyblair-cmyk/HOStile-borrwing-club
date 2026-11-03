/*
 * File: 03_memory_shield.rs
 * Topic: Safe Systems Programming - Guarded Memory Allocation & Boundary Checking
 * Language: Rust (Edition 2021)
 * Description: Implements a memory-safe ring buffer with bounds verification,
 *              canary integrity checks, and zeroization on drop to prevent data leakage.
 */

use std::fmt;
use std::ops::{Index, IndexMut};
use std::sync::atomic::{AtomicUsize, Ordering};

static ALLOCATION_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, PartialEq, Eq)]
pub enum MemoryError {
    OutOfBoundsAccess { index: usize, capacity: usize },
    IntegrityCheckFailed,
    BufferOverflowAttempt,
    AllocationFailed,
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryError::OutOfBoundsAccess { index, capacity } => {
                write!(f, "Access out of bounds: index {} >= capacity {}", index, capacity)
            }
            MemoryError::IntegrityCheckFailed => write!(f, "Canary validation failed: memory corruption suspected"),
            MemoryError::BufferOverflowAttempt => write!(f, "Operation rejected: write exceeds buffer capacity"),
            MemoryError::AllocationFailed => write!(f, "Memory allocation request failed"),
        }
    }
}

impl std::error::Error for MemoryError {}

const CANARY_MAGIC: u64 = 0xDEAD_BEEF_CAFE_BABE;

/// A safe memory region flanked by guard integrity canaries.
pub struct GuardedBuffer<T: Copy + Default> {
    head_canary: u64,
    data: Vec<T>,
    capacity: usize,
    tail_canary: u64,
}

impl<T: Copy + Default> GuardedBuffer<T> {
    pub fn new(capacity: usize) -> Result<Self, MemoryError> {
        if capacity == 0 {
            return Err(MemoryError::AllocationFailed);
        }

        ALLOCATION_COUNTER.fetch_add(1, Ordering::SeqCst);

        Ok(GuardedBuffer {
            head_canary: CANARY_MAGIC,
            data: vec![T::default(); capacity],
            capacity,
            tail_canary: CANARY_MAGIC,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), MemoryError> {
        if self.head_canary != CANARY_MAGIC || self.tail_canary != CANARY_MAGIC {
            Err(MemoryError::IntegrityCheckFailed)
        } else {
            Ok(())
        }
    }

    pub fn write_slice(&mut self, offset: usize, src: &[T]) -> Result<usize, MemoryError> {
        self.verify_integrity()?;

        if offset >= self.capacity {
            return Err(MemoryError::OutOfBoundsAccess {
                index: offset,
                capacity: self.capacity,
            });
        }

        if offset + src.len() > self.capacity {
            return Err(MemoryError::BufferOverflowAttempt);
        }

        self.data[offset..offset + src.len()].copy_from_slice(src);
        Ok(src.len())
    }

    pub fn read_slice(&self, offset: usize, len: usize) -> Result<&[T], MemoryError> {
        self.verify_integrity()?;

        if offset + len > self.capacity {
            return Err(MemoryError::OutOfBoundsAccess {
                index: offset + len,
                capacity: self.capacity,
            });
        }

        Ok(&self.data[offset..offset + len])
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl<T: Copy + Default> Index<usize> for GuardedBuffer<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        if self.verify_integrity().is_err() {
            panic!("Memory integrity violation detected during index operation");
        }
        &self.data[index]
    }
}

impl<T: Copy + Default> IndexMut<usize> for GuardedBuffer<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        if self.verify_integrity().is_err() {
            panic!("Memory integrity violation detected during mutable index operation");
        }
        &mut self.data[index]
    }
}

impl<T: Copy + Default> Drop for GuardedBuffer<T> {
    fn drop(&mut self) {
        // Zeroize memory on release to clear sensitive residual data
        for elem in self.data.iter_mut() {
            *elem = T::default();
        }
        self.head_canary = 0;
        self.tail_canary = 0;
        ALLOCATION_COUNTER.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct SecureRingBuffer {
    buffer: GuardedBuffer<u8>,
    write_ptr: usize,
    read_ptr: usize,
    size: usize,
}

impl SecureRingBuffer {
    pub fn new(capacity: usize) -> Result<Self, MemoryError> {
        Ok(SecureRingBuffer {
            buffer: GuardedBuffer::new(capacity)?,
            write_ptr: 0,
            read_ptr: 0,
            size: 0,
        })
    }

    pub fn push(&mut self, byte: u8) -> Result<(), MemoryError> {
        if self.size == self.buffer.capacity() {
            return Err(MemoryError::BufferOverflowAttempt);
        }

        let cap = self.buffer.capacity();
        self.buffer.write_slice(self.write_ptr, &[byte])?;
        self.write_ptr = (self.write_ptr + 1) % cap;
        self.size += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Result<u8, MemoryError> {
        if self.size == 0 {
            return Err(MemoryError::OutOfBoundsAccess { index: 0, capacity: 0 });
        }

        let byte = self.buffer[self.read_ptr];
        let cap = self.buffer.capacity();
        self.read_ptr = (self.read_ptr + 1) % cap;
        self.size -= 1;
        Ok(byte)
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn len(&self) -> usize {
        self.size
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Secure Memory Allocator Guard System ===");

    let mut secure_buf = GuardedBuffer::<u8>::new(64)?;
    println!("[+] Allocated safe buffer of size {}", secure_buf.capacity());

    let payload = b"SECURE_TELEMETRY_DATA_PACKET";
    secure_buf.write_slice(0, payload)?;
    println!("[+] Data successfully written to memory buffer");

    secure_buf.verify_integrity()?;
    println!("[+] Canary verification passed. Integrity intact.");

    let read_back = secure_buf.read_slice(0, payload.len())?;
    println!("[+] Read verification: {}", String::from_utf8_lossy(read_back));

    let mut ring = SecureRingBuffer::new(16)?;
    for b in b"TEST_STREAM" {
        ring.push(*b)?;
    }

    print!("[+] Ring Buffer Stream Read: ");
    while !ring.is_empty() {
        print!("{}", ring.pop()? as char);
    }
    println!();

    println!("[+] Active Allocations: {}", ALLOCATION_COUNTER.load(Ordering::SeqCst));
    drop(secure_buf);
    drop(ring);
    println!("[+] Memory safely zeroed and dropped. Active Allocations: {}", ALLOCATION_COUNTER.load(Ordering::SeqCst));

    Ok(())
}