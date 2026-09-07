#[cfg(windows)]
mod win_rng {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }

    pub fn fill(buf: &mut [u8]) -> Result<(), String> {
        if buf.is_empty() {
            return Ok(());
        }
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(format!("BCryptGenRandom failed with NTSTATUS: {:#010x}", status))
        }
    }
}

#[cfg(not(windows))]
mod unix_rng {
    use std::fs::File;
    use std::io::Read;

    pub fn fill(buf: &mut [u8]) -> Result<(), String> {
        let mut file = File::open("/dev/urandom")
            .map_err(|e| format!("Failed to open /dev/urandom: {}", e))?;
        file.read_exact(buf)
            .map_err(|e| format!("Failed to read /dev/urandom: {}", e))?;
        Ok(())
    }
}

pub fn random_bytes(buf: &mut [u8]) -> Result<(), String> {
    #[cfg(windows)]
    {
        win_rng::fill(buf)
    }
    #[cfg(not(windows))]
    {
        unix_rng::fill(buf)
    }
}

pub fn random_32() -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    random_bytes(&mut out)?;
    Ok(out)
}

pub fn random_12() -> Result<[u8; 12], String> {
    let mut out = [0u8; 12];
    random_bytes(&mut out)?;
    Ok(out)
}

pub fn random_16() -> Result<[u8; 16], String> {
    let mut out = [0u8; 16];
    random_bytes(&mut out)?;
    Ok(out)
}
