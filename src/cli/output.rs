use crate::core::totp::TotpResult;

pub fn print_totp_result(issuer: &str, result: &TotpResult) {
    println!("\x1b[1m{}\x1b[0m\n", issuer);
    println!("Current : \x1b[1;36m{}\x1b[0m", result.current_formatted);
    println!("Next    : \x1b[90m{}\x1b[0m", result.next_formatted);
    println!("Expires : \x1b[33m{}s\x1b[0m", result.expires_in);
    println!("Period  : {}s", result.period);
}

pub fn print_totp_json(result: &TotpResult) {
    println!("{{");
    println!("  \"current\": \"{}\",", result.current);
    println!("  \"next\": \"{}\",", result.next);
    println!("  \"expires_in\": {},", result.expires_in);
    println!("  \"period\": {}", result.period);
    println!("}}");
}

pub fn print_passkey_request_box(rp_id: &str, account: &str) {
    println!("╭──────────────────────────────────────╮");
    println!("│          \x1b[1mPASSKEY REQUEST\x1b[0m             │");
    println!("├──────────────────────────────────────┤");
    println!("│                                      │");
    println!("│ Relying Party:                       │");
    println!("│ \x1b[1;36m{:<36}\x1b[0m │", rp_id);
    println!("│                                      │");
    println!("│ Account:                             │");
    println!("│ \x1b[1;32m{:<36}\x1b[0m │", account);
    println!("│                                      │");
    println!("│ Operation:                           │");
    println!("│ Authenticate                         │");
    println!("│                                      │");
    println!("│ User verification: \x1b[1;33mREQUIRED\x1b[0m          │");
    println!("│                                      │");
    println!("│ Allow this operation? [y/N]          │");
    println!("╰──────────────────────────────────────╯");
}

pub fn print_passkey_reg_box(rp_id: &str, account: &str) {
    println!("╭──────────────────────────────────────╮");
    println!("│         \x1b[1mPASSKEY REGISTRATION\x1b[0m         │");
    println!("├──────────────────────────────────────┤");
    println!("│                                      │");
    println!("│ Relying Party:                       │");
    println!("│ \x1b[1;36m{:<36}\x1b[0m │", rp_id);
    println!("│                                      │");
    println!("│ User:                                │");
    println!("│ \x1b[1;32m{:<36}\x1b[0m │", account);
    println!("│                                      │");
    println!("│ New credential will be stored in     │");
    println!("│ the CredShell vault.                 │");
    println!("│                                      │");
    println!("│ Create passkey? [y/N]                │");
    println!("╰──────────────────────────────────────╯");
}

pub fn print_passkey_active_banner() {
    println!("╭──────────────────────────────────────╮");
    println!("│              \x1b[1mCREDSHELL\x1b[0m               │");
    println!("│                                      │");
    println!("│ \x1b[1;32mPasskey authenticator active\x1b[0m         │");
    println!("│                                      │");
    println!("│ Listening for WebAuthn requests...   │");
    println!("│                                      │");
    println!("│ Ctrl+C to exit                       │");
    println!("╰──────────────────────────────────────╯");
}
