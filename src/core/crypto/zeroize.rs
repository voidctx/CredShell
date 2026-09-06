use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[inline]
pub fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            ptr::write_volatile(b, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline]
pub fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub struct Zeroizing<T: AsMut<[u8]>> {
    inner: T,
}

impl<T: AsMut<[u8]>> Zeroizing<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: AsMut<[u8]>> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: AsMut<[u8]>> core::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: AsMut<[u8]>> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        zeroize(self.inner.as_mut());
    }
}
