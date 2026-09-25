use credshell::cli::args::{parse_cli, Command};
use credshell::cli::commands::{
    get_or_unlock_vault, handle_export, handle_import, handle_passkey, handle_sync_rx,
    handle_sync_tx, handle_totp_add, handle_totp_delete, handle_totp_get, handle_totp_list,
    handle_vault_change_password, handle_vault_status,
};
use std::env;
use std::process;

fn print_help() {
    println!("\x1b[1;36mCredShell\x1b[0m — Zero-Crate, Zero-Daemon Local Vault Authenticator (TOTP + WebAuthn Passkeys)\n");
    println!("\x1b[1mUSAGE:\x1b[0m");
    println!("  credshell <command> [subcommand] [-v vault_path]\n");

    println!("\x1b[1mCOMMANDS:\x1b[0m");
    println!("  \x1b[33mtotp\x1b[0m");
    println!("    get <id> [--json]                       Generate current 6-digit TOTP code");
    println!("    add [id] <secret_or_otpauth_uri>        Store secret or otpauth:// URI in vault");
    println!("      Options: --issuer <name> --account <user> --algo <SHA-1|SHA-256|SHA-512>");
    println!("    list [--json]                           List all registered TOTP accounts");
    println!("    delete <id>                             Remove a TOTP entry from the vault\n");

    println!("  \x1b[33mpasskey\x1b[0m");
    println!("    (default) [--port 5209] [-y]            Start active platform authenticator (login & register)");
    println!("    list                                    List all stored active Passkeys in vault");
    println!("    list-bak                                List all Android replaced backup passkeys");
    println!("    restore <id-bak>                        Restore a backup passkey to active");
    println!("    delete <id_or_rp>                       Delete a passkey by ID or Relying Party");
    println!("    install-manifest                        Install Native Messaging manifest for Chrome/Edge\n");

    println!("  \x1b[33msync\x1b[0m");
    println!("    rx [--port 7443]                        Start encrypted vault receiver listener");
    println!("    tx <target_ip_or_host[:port]>           Transmitter: sync vault to peer");
    println!("    export [path.kxb]                       Export encrypted AES-256-GCM backup blob");
    println!("    import <path.kxb>                       Transactionally merge/import backup blob\n");

    println!("  \x1b[33mvault\x1b[0m");
    println!("    status                                  Display vault statistics & info");
    println!("    create                                  Initialize a new encrypted vault");
    println!("    change-password [new_pass]              Re-encrypt vault with a new master passphrase\n");

    println!("\x1b[1mFLAGS:\x1b[0m");
    println!("  -v, --vault <file_path>                   Specify vault file path (default: .credshell/vault.kdb)");
    println!("  -h, --help                                Print this help message\n");

    println!("\x1b[1mEXAMPLES:\x1b[0m");
    println!("  credshell passkey");
    println!("  credshell totp add \"otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP\"");
    println!("  credshell totp add github-work JBSWY3DPEHPK3PXP --issuer GitHub");
    println!("  credshell totp get github-work");
    println!("  credshell totp list -v mydir/vault2.kbd");
    println!("  credshell vault status -v mydir/vault2.kbd\n");
}

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();

    let config = match parse_cli(&raw_args) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("\x1b[1;31mError:\x1b[0m {}", err);
            process::exit(1);
        }
    };

    let vault_path = &config.vault_path;

    let result = match config.command {
        Command::Help => {
            print_help();
            Ok(())
        }
        Command::TotpGet { name, json } => handle_totp_get(vault_path, &name, json),
        Command::TotpAdd { id, secret_or_uri, issuer, account, algo } => {
            handle_totp_add(vault_path, id, &secret_or_uri, issuer, account, algo)
        }
        Command::TotpList { json } => handle_totp_list(vault_path, json),
        Command::TotpDelete { name } => handle_totp_delete(vault_path, &name),
        Command::Passkey { subaction } => handle_passkey(vault_path, subaction),
        Command::SyncRx { port } => handle_sync_rx(vault_path, port),
        Command::SyncTx { target } => handle_sync_tx(vault_path, &target),
        Command::Export { output_path } => handle_export(vault_path, &output_path),
        Command::Import { input_path } => handle_import(vault_path, &input_path),
        Command::VaultStatus => handle_vault_status(vault_path),
        Command::VaultChangePassword { new_password } => {
            handle_vault_change_password(vault_path, new_password)
        }
        Command::Init => {
            println!("Initializing CredShell vault at {:?}...", vault_path);
            match get_or_unlock_vault(vault_path, None) {
                Ok(_) => {
                    println!("✓ Vault is ready at {:?}", vault_path);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    };

    if let Err(err) = result {
        eprintln!("\x1b[1;31mError:\x1b[0m {}", err);
        process::exit(1);
    }
}
