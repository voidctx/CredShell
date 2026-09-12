use crate::core::vault::storage::default_vault_path;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq)]
pub struct CliConfig {
    pub vault_path: PathBuf,
    pub command: Command,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    Help,
    TotpGet {
        name: String,
        json: bool,
    },
    TotpAdd {
        id: Option<String>,
        secret_or_uri: String,
        issuer: Option<String>,
        account: Option<String>,
        algo: Option<String>,
    },
    TotpList {
        json: bool,
    },
    TotpDelete {
        name: String,
    },
    Passkey {
        subaction: Option<PasskeyAction>,
    },
    SyncRx {
        port: u16,
    },
    SyncTx {
        target: String,
    },
    Export {
        output_path: String,
    },
    Import {
        input_path: String,
    },
    VaultStatus,
    VaultChangePassword {
        new_password: Option<String>,
    },
    Init,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PasskeyAction {
    Listen { port: u16, auto_approve: bool },
    List,
    ListBak,
    Restore { id: String },
    Delete { id_or_rp: String },
    InstallManifest,
}

pub fn parse_cli(args: &[String]) -> Result<CliConfig, String> {
    let mut explicit_vault_path: Option<PathBuf> = None;
    let mut filtered = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-p" || arg == "--password" || arg.starts_with("-p=") || arg.starts_with("--password=") {
            return Err("The '-p' / '--password' flag has been removed. Please supply your master password via the CREDSHELL_PASSWORD or CREDSHELL_PASSPHRASE environment variable, or enter it interactively.".to_string());
        } else if arg == "-v" || arg == "--vault" {
            if i + 1 < args.len() {
                explicit_vault_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            } else {
                return Err("Flag '-v' / '--vault' requires a path value".to_string());
            }
        } else if let Some(val) = arg.strip_prefix("-v=") {
            explicit_vault_path = Some(PathBuf::from(val));
            i += 1;
        } else if let Some(val) = arg.strip_prefix("--vault=") {
            explicit_vault_path = Some(PathBuf::from(val));
            i += 1;
        } else {
            filtered.push(arg.clone());
            i += 1;
        }
    }

    let vault_path = explicit_vault_path.unwrap_or_else(default_vault_path);
    let command = parse_command(&filtered)?;

    Ok(CliConfig {
        vault_path,
        command,
    })
}

fn parse_command(args: &[String]) -> Result<Command, String> {
    if args.is_empty() {
        return Ok(Command::Help);
    }

    match args[0].as_str() {
        "help" | "-h" | "--help" => Ok(Command::Help),
        "init" => Ok(Command::Init),
        "export" => {
            let path = if args.len() > 1 {
                args[1].clone()
            } else {
                "credshell_backup.kxb".to_string()
            };
            Ok(Command::Export { output_path: path })
        }
        "import" => {
            if args.len() < 2 {
                return Err("Usage: credshell [vault] import <file>".to_string());
            }
            Ok(Command::Import { input_path: args[1].clone() })
        }
        "totp" => {
            if args.len() < 2 {
                return Ok(Command::TotpList { json: false });
            }
            if args[1].starts_with("otpauth://") {
                return Ok(Command::TotpAdd {
                    id: None,
                    secret_or_uri: args[1].clone(),
                    issuer: None,
                    account: None,
                    algo: None,
                });
            }
            match args[1].as_str() {
                "get" => {
                    if args.len() < 3 {
                        return Err("Usage: credshell totp get <id> [--json] [-v vault]".to_string());
                    }
                    let name = args[2].clone();
                    let json = args.iter().any(|a| a == "--json");
                    Ok(Command::TotpGet { name, json })
                }
                "add" => {
                    if args.len() < 3 {
                        return Err("Usage: credshell totp add [id] <secret_or_otpauth_uri> [--issuer <iss>] [--account <acc>] [--algo <algo>] [-v vault]".to_string());
                    }
                    let mut pos = Vec::new();
                    let mut issuer = None;
                    let mut account = None;
                    let mut algo = None;

                    let mut i = 2;
                    while i < args.len() {
                        match args[i].as_str() {
                            "--issuer" if i + 1 < args.len() => {
                                issuer = Some(args[i + 1].clone());
                                i += 2;
                            }
                            "--account" if i + 1 < args.len() => {
                                account = Some(args[i + 1].clone());
                                i += 2;
                            }
                            "--algo" if i + 1 < args.len() => {
                                algo = Some(args[i + 1].clone());
                                i += 2;
                            }
                            arg if !arg.starts_with('-') => {
                                pos.push(arg.to_string());
                                i += 1;
                            }
                            _ => i += 1,
                        }
                    }

                    if pos.is_empty() {
                        return Err("Usage: credshell totp add [id] <secret_or_otpauth_uri> [options]".to_string());
                    }

                    let (id, secret_or_uri) = if pos.len() == 1 {
                        (None, pos[0].clone())
                    } else {
                        (Some(pos[0].clone()), pos[1].clone())
                    };

                    Ok(Command::TotpAdd {
                        id,
                        secret_or_uri,
                        issuer,
                        account,
                        algo,
                    })
                }
                "list" => {
                    let json = args.iter().any(|a| a == "--json");
                    Ok(Command::TotpList { json })
                }
                "delete" | "rm" => {
                    if args.len() < 3 {
                        return Err("Usage: credshell totp delete <id> [-v vault]".to_string());
                    }
                    Ok(Command::TotpDelete { name: args[2].clone() })
                }
                other => {
                    let json = args.iter().any(|a| a == "--json");
                    Ok(Command::TotpGet { name: other.to_string(), json })
                }
            }
        }
        "passkey" => {
            let mut port = 5209;
            let mut auto_approve = false;
            let mut subaction_opt: Option<&str> = None;
            let mut pos_args = Vec::new();

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--port" if i + 1 < args.len() => {
                        if let Ok(p) = args[i + 1].parse::<u16>() {
                            port = p;
                        }
                        i += 2;
                    }
                    "-y" | "--yes" | "--auto-approve" => {
                        auto_approve = true;
                        i += 1;
                    }
                    arg if !arg.starts_with('-') => {
                        if subaction_opt.is_none() {
                            subaction_opt = Some(arg);
                        } else {
                            pos_args.push(arg.to_string());
                        }
                        i += 1;
                    }
                    _ => i += 1,
                }
            }

            match subaction_opt.unwrap_or("listen") {
                "listen" => Ok(Command::Passkey {
                    subaction: Some(PasskeyAction::Listen { port, auto_approve }),
                }),
                "list" => Ok(Command::Passkey {
                    subaction: Some(PasskeyAction::List),
                }),
                "list-bak" | "list_bak" | "backups" => Ok(Command::Passkey {
                    subaction: Some(PasskeyAction::ListBak),
                }),
                "restore" => {
                    if pos_args.is_empty() {
                        return Err("Usage: credshell passkey restore <id-bak> [-v vault]".to_string());
                    }
                    Ok(Command::Passkey {
                        subaction: Some(PasskeyAction::Restore {
                            id: pos_args[0].clone(),
                        }),
                    })
                }
                "install-manifest" => Ok(Command::Passkey {
                    subaction: Some(PasskeyAction::InstallManifest),
                }),
                "delete" | "rm" => {
                    if pos_args.is_empty() {
                        return Err("Usage: credshell passkey delete <id_or_rp> [-v vault]".to_string());
                    }
                    Ok(Command::Passkey {
                        subaction: Some(PasskeyAction::Delete {
                            id_or_rp: pos_args[0].clone(),
                        }),
                    })
                }
                _ => Ok(Command::Passkey {
                    subaction: Some(PasskeyAction::Listen { port, auto_approve }),
                }),
            }
        }
        "sync" => {
            if args.len() < 2 {
                return Err("Usage: credshell [vault] sync [rx|tx|export|import]".to_string());
            }
            match args[1].as_str() {
                "rx" => {
                    let mut port = 7443;
                    let mut i = 2;
                    while i < args.len() {
                        if args[i] == "--port" && i + 1 < args.len() {
                            if let Ok(p) = args[i + 1].parse::<u16>() {
                                port = p;
                            }
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                    Ok(Command::SyncRx { port })
                }
                "tx" => {
                    if args.len() < 3 {
                        return Err("Usage: credshell [vault] sync tx <target_ip_or_host[:port]>".to_string());
                    }
                    let mut target = args[2].clone();
                    if !target.contains(':') || (target.starts_with('[') && !target.contains("]:")) {
                        target = format!("{}:7443", target);
                    }
                    Ok(Command::SyncTx { target })
                }
                "export" => {
                    let path = if args.len() > 2 {
                        args[2].clone()
                    } else {
                        "credshell_backup.kxb".to_string()
                    };
                    Ok(Command::Export { output_path: path })
                }
                "import" => {
                    if args.len() < 3 {
                        return Err("Usage: credshell [vault] sync import <file>".to_string());
                    }
                    Ok(Command::Import { input_path: args[2].clone() })
                }
                _ => Err(format!("Unknown sync command: '{}'", args[1])),
            }
        }
        "vault" => {
            if args.len() < 2 {
                return Ok(Command::VaultStatus);
            }
            match args[1].as_str() {
                "status" | "info" => Ok(Command::VaultStatus),
                "create" | "init" => Ok(Command::Init),
                "change-password" | "passwd" => {
                    let new_pass = if args.len() > 2 {
                        Some(args[2].clone())
                    } else {
                        None
                    };
                    Ok(Command::VaultChangePassword { new_password: new_pass })
                }
                _ => Err(format!("Unknown vault command: '{}'. Options: status, create, change-password", args[1])),
            }
        }
        unknown => Err(format!("Unknown command: '{}'. Run 'credshell --help' for usage.", unknown)),
    }
}
