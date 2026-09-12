use std::env;

pub fn current_platform_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "Windows"
    }
    #[cfg(target_os = "macos")]
    {
        "macOS"
    }
    #[cfg(target_os = "linux")]
    {
        "Linux"
    }
    #[cfg(target_os = "android")]
    {
        "Android"
    }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "macos",
        target_os = "linux",
        target_os = "android"
    )))]
    {
        "Generic POSIX"
    }
}

pub fn get_default_device_name() -> String {
    if let Ok(name) = env::var("COMPUTERNAME") {
        if !name.trim().is_empty() {
            return name.trim().to_lowercase();
        }
    }
    if let Ok(name) = env::var("HOSTNAME") {
        if !name.trim().is_empty() {
            return name.trim().to_lowercase();
        }
    }
    format!("credshell-{}", current_platform_name().to_lowercase())
}

#[cfg(windows)]
pub fn prompt_passphrase(prompt_text: &str) -> Result<String, String> {
    use std::io::{self, Write};
    eprint!("{}", prompt_text);
    let _ = io::stderr().flush();

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> *mut core::ffi::c_void;
        fn GetConsoleMode(hConsoleHandle: *mut core::ffi::c_void, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: *mut core::ffi::c_void, dwMode: u32) -> i32;
    }
    const STD_INPUT_HANDLE: u32 = 0xFFFFFFF6;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut old_mode = 0u32;
    let mut mode_changed = false;
    if !handle.is_null() && unsafe { GetConsoleMode(handle, &mut old_mode) } != 0 {
        let new_mode = old_mode & !ENABLE_ECHO_INPUT;
        if unsafe { SetConsoleMode(handle, new_mode) } != 0 {
            mode_changed = true;
        }
    }

    let mut input = String::new();
    let read_res = io::stdin().read_line(&mut input);

    if mode_changed {
        unsafe {
            SetConsoleMode(handle, old_mode);
        }
    }
    eprintln!();

    read_res.map_err(|e| format!("Failed to read passphrase: {}", e))?;
    let pass = input.trim_end_matches(['\r', '\n']).to_string();
    if pass.is_empty() {
        return Err("Passphrase cannot be empty".to_string());
    }
    Ok(pass)
}

#[cfg(not(windows))]
pub fn prompt_passphrase(prompt_text: &str) -> Result<String, String> {
    use std::io::{self, Write};
    eprint!("{}", prompt_text);
    let _ = io::stderr().flush();

    let _ = std::process::Command::new("stty").arg("-echo").status();
    let mut input = String::new();
    let read_res = io::stdin().read_line(&mut input);
    let _ = std::process::Command::new("stty").arg("echo").status();
    eprintln!();

    read_res.map_err(|e| format!("Failed to read passphrase: {}", e))?;
    let pass = input.trim_end_matches(['\r', '\n']).to_string();
    if pass.is_empty() {
        return Err("Passphrase cannot be empty".to_string());
    }
    Ok(pass)
}

#[cfg(windows)]
pub fn native_gui_confirm(title: &str, message: &str) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(
            hwnd: *mut core::ffi::c_void,
            lpText: *const u16,
            lpCaption: *const u16,
            uType: u32,
        ) -> i32;
    }

    let wide_msg: Vec<u16> = OsStr::new(message).encode_wide().chain(Some(0)).collect();
    let wide_title: Vec<u16> = OsStr::new(title).encode_wide().chain(Some(0)).collect();
    let res = unsafe {
        MessageBoxW(
            core::ptr::null_mut(),
            wide_msg.as_ptr(),
            wide_title.as_ptr(),
            0x04 | 0x20 | 0x40000,
        )
    };
    res == 6
}

#[cfg(target_os = "macos")]
pub fn native_gui_confirm(title: &str, message: &str) -> bool {
    let script = format!(
        "display dialog {:?} with title {:?} buttons {{\"Deny\", \"Allow\"}} default button \"Allow\"",
        message, title
    );
    if let Ok(output) = std::process::Command::new("osascript").args(&["-e", &script]).output() {
        String::from_utf8_lossy(&output.stdout).contains("button returned:Allow")
    } else {
        false
    }
}

#[cfg(all(unix, not(target_os = "macos"), not(target_os = "android")))]
pub fn native_gui_confirm(title: &str, message: &str) -> bool {
    if let Ok(status) = std::process::Command::new("zenity")
        .args(&["--question", "--title", title, "--text", message])
        .status()
    {
        return status.success();
    }
    if let Ok(status) = std::process::Command::new("kdialog")
        .args(&["--title", title, "--yesno", message])
        .status()
    {
        return status.success();
    }
    false
}

#[cfg(target_os = "android")]
pub fn native_gui_confirm(title: &str, message: &str) -> bool {
    if let Ok(output) = std::process::Command::new("termux-dialog")
        .args(&["confirm", "-t", title, "-i", message])
        .output()
    {
        if output.status.success() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            if out_str.contains("\"yes\"") || out_str.contains("\"text\": \"yes\"") {
                return true;
            } else if out_str.contains("\"no\"") {
                return false;
            }
        }
    }

    use std::io::{self, Write};
    eprint!("\x1b[1;33m[CredShell Confirmation]\x1b[0m {}: {} (y/N): ", title, message);
    let _ = io::stderr().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        let trimmed = input.trim().to_lowercase();
        if trimmed == "y" || trimmed == "yes" {
            return true;
        }
    }

    false
}
