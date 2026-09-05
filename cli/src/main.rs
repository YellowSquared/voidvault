mod client;
mod config;
mod crypto;
mod model;

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use clap::{Parser, Subcommand, ValueEnum};
use tabwriter::TabWriter;

use client::VaultClient;
use config::{get_default_capsule_path, load_config, save_config, write_secure_file};
use crypto::{
    calculate_locator, decrypt_entries, derive_prf_key, derive_simulated_prf, encrypt_entries,
    generate_vmk, unwrap_vmk, wrap_vmk, DEFAULT_DEV_PASSPHRASE,
};
use model::{KeySlot, VaultCapsule, VaultEntry};

#[derive(Parser)]
#[command(
    name = "voidvault",
    version = "0.2.0",
    about = "Zero-knowledge FIDO2 hardware attestation password vault CLI",
    long_about = "VoidVault: Minimalist, blind zero-knowledge password vault CLI with full WebAuthn PRF parity."
)]
struct Cli {
    /// Custom path to vault capsule file [env: VOIDVAULT_FILE]
    #[arg(short = 'F', long, global = true)]
    file: Option<PathBuf>,

    /// Relay server URL [env: VOIDVAULT_SERVER]
    #[arg(short = 'S', long, global = true)]
    server: Option<String>,

    /// Passphrase or raw seed for key derivation [env: VOIDVAULT_KEY]
    #[arg(short = 'K', long, global = true)]
    key: Option<String>,

    /// Quick Dev mode: use default simulated PRF key without prompt
    #[arg(long, global = true)]
    dev: bool,

    /// Suppress informational stderr messages
    #[arg(short = 'q', long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault capsule
    Init {
        /// Force overwrite if vault already exists
        #[arg(short, long)]
        force: bool,
        /// Label for initial keyslot
        #[arg(short, long, default_value = "Primary Security Key")]
        label: String,
    },

    /// Retrieve a credential by title or domain
    Get {
        /// Secret title or domain to retrieve
        query: String,

        /// Specific field to extract
        #[arg(short, long, value_enum, default_value_t = FieldType::Password)]
        field: FieldType,

        /// Output full entry as JSON
        #[arg(long)]
        json: bool,
    },

    /// List all stored credentials
    #[command(alias = "ls")]
    List {
        /// Optional search query filter
        query: Option<String>,

        /// Output as JSON array
        #[arg(long)]
        json: bool,
    },

    /// Add a new secret to the vault
    Add {
        /// Secret title (e.g. GitHub, AWS)
        title: String,

        /// Associated website domain (e.g. github.com)
        #[arg(short, long)]
        domain: Option<String>,

        /// Username or email
        #[arg(short, long)]
        username: Option<String>,

        /// Forbidden: passing passwords via CLI flag is blocked to prevent shell history leaks
        #[arg(short, long, hide = true)]
        password: Option<String>,

        /// Automatically generate a random password
        #[arg(short = 'g', long)]
        gen_pass: bool,

        /// Generated password length
        #[arg(short = 'l', long, default_value_t = 20)]
        length: usize,

        /// Exclude symbols in generated password
        #[arg(long)]
        no_symbols: bool,

        /// Notes or multiline metadata
        #[arg(short, long)]
        notes: Option<String>,

        /// Skip pushing update to remote server
        #[arg(long)]
        no_sync: bool,
    },

    /// Remove a secret from the vault
    #[command(alias = "delete")]
    Rm {
        /// Secret title or domain to remove
        query: String,

        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,

        /// Skip pushing update to remote server
        #[arg(long)]
        no_sync: bool,
    },

    /// Synchronize local vault with remote relay server
    Sync,

    /// Pull latest vault capsule from remote server
    Pull,

    /// Push local vault capsule to remote server
    Push,

    /// Import vault entries from a .voidvault backup file
    Import {
        /// Path to .voidvault or backup JSON file
        source: PathBuf,
    },

    /// Export vault capsule as .voidvault backup file
    Export {
        /// Output path (defaults to stdout if omitted)
        destination: Option<PathBuf>,
    },

    /// View or update CLI configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Check vault status, sync version, and server health
    Status,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum FieldType {
    Password,
    Username,
    Domain,
    Title,
    Notes,
    All,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show all configuration values
    Show,
    /// Set a configuration option (server, mode)
    Set { key: String, value: String },
    /// Get a specific configuration value
    Get { key: String },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(err) = run_cli(cli).await {
        eprintln!("[!] Error: {}", err);
        std::process::exit(1);
    }
}

async fn run_cli(cli: Cli) -> Result<(), String> {
    let capsule_path = cli.file.unwrap_or_else(get_default_capsule_path);
    let app_cfg = load_config();
    let server_url = cli
        .server
        .or(app_cfg.server_url.clone())
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    match cli.command {
        Commands::Init { force, label } => {
            cmd_init(&capsule_path, force, &label, cli.dev, cli.key.as_deref(), cli.quiet)
        }
        Commands::Get { query, field, json } => {
            cmd_get(&capsule_path, &query, field, json, cli.dev, cli.key.as_deref())
        }
        Commands::List { query, json } => {
            cmd_list(&capsule_path, query.as_deref(), json, cli.dev, cli.key.as_deref())
        }
        Commands::Add {
            title,
            domain,
            username,
            password,
            gen_pass,
            length,
            no_symbols,
            notes,
            no_sync,
        } => {
            cmd_add(
                &capsule_path,
                &title,
                domain,
                username,
                password,
                gen_pass,
                length,
                no_symbols,
                notes,
                no_sync,
                &server_url,
                cli.dev,
                cli.key.as_deref(),
                cli.quiet,
            )
            .await
        }
        Commands::Rm { query, yes, no_sync } => {
            cmd_rm(
                &capsule_path,
                &query,
                yes,
                no_sync,
                &server_url,
                cli.dev,
                cli.key.as_deref(),
                cli.quiet,
            )
            .await
        }
        Commands::Sync => {
            cmd_sync(&capsule_path, &server_url, cli.dev, cli.key.as_deref(), cli.quiet).await
        }
        Commands::Pull => {
            cmd_pull(&capsule_path, &server_url, cli.quiet).await
        }
        Commands::Push => {
            cmd_push(&capsule_path, &server_url, cli.quiet).await
        }
        Commands::Import { source } => {
            cmd_import(&capsule_path, &source, cli.quiet)
        }
        Commands::Export { destination } => {
            cmd_export(&capsule_path, destination.as_deref(), cli.quiet)
        }
        Commands::Config { action } => {
            cmd_config(action)
        }
        Commands::Status => {
            cmd_status(&capsule_path, &server_url).await
        }
    }
}

fn resolve_prf_key(dev_mode: bool, key_arg: Option<&str>) -> [u8; 32] {
    if dev_mode {
        return derive_simulated_prf(DEFAULT_DEV_PASSPHRASE);
    }
    if let Some(k) = key_arg {
        return derive_simulated_prf(k);
    }
    if let Ok(env_key) = std::env::var("VOIDVAULT_KEY") {
        if !env_key.is_empty() {
            return derive_simulated_prf(&env_key);
        }
    }
    // Interactive prompt
    eprint!("[?] Touch Security Key / Enter Key Passphrase (press Enter for default dev key): ");
    let _ = io::stderr().flush();
    if let Ok(pass) = rpassword::read_password() {
        if !pass.trim().is_empty() {
            return derive_simulated_prf(pass.trim());
        }
    }
    derive_simulated_prf(DEFAULT_DEV_PASSPHRASE)
}

fn load_capsule_from_disk(path: &Path) -> Result<VaultCapsule, String> {
    if !path.exists() {
        return Err(format!(
            "Vault capsule not found at {:?}. Run 'voidvault init' to create one.",
            path
        ));
    }
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read vault capsule at {:?}: {}", path, e))?;
    let capsule: VaultCapsule = serde_json::from_str(&data)
        .map_err(|e| format!("Failed to parse vault capsule JSON: {}", e))?;
    Ok(capsule)
}

fn unlock_capsule(
    capsule: &VaultCapsule,
    prf_secret: &[u8; 32],
) -> Result<([u8; 32], Vec<VaultEntry>), String> {
    let prf_key = derive_prf_key(prf_secret)?;
    let mut vmk: Option<[u8; 32]> = None;

    for slot in &capsule.key_slots {
        if let Ok(unwrapped) = unwrap_vmk(&slot.wrapped_vmk, &prf_key) {
            vmk = Some(unwrapped);
            break;
        }
    }

    let vmk = vmk.ok_or_else(|| {
        "This security key is not enrolled in this vault capsule (decryption failed).".to_string()
    })?;

    let entries = decrypt_entries(&capsule.payload, &vmk)?;
    Ok((vmk, entries))
}

fn cmd_init(
    path: &Path,
    force: bool,
    label: &str,
    dev_mode: bool,
    key_arg: Option<&str>,
    quiet: bool,
) -> Result<(), String> {
    if path.exists() && !force {
        return Err(format!(
            "Vault capsule already exists at {:?}. Use --force to overwrite.",
            path
        ));
    }

    let prf_secret = resolve_prf_key(dev_mode, key_arg);
    let prf_key = derive_prf_key(&prf_secret)?;

    let vmk = generate_vmk();
    let wrapped_vmk = wrap_vmk(&vmk, &prf_key)?;

    let cred_id = format!("cred_{}", hex::encode(&prf_secret[..8]));
    let locator = calculate_locator(&cred_id);

    let empty_entries: Vec<VaultEntry> = Vec::new();
    let payload = encrypt_entries(&empty_entries, &vmk)?;

    let capsule = VaultCapsule {
        format: "voidvault-multi-keyslot-v1".to_string(),
        key_slots: vec![KeySlot {
            id: format!("slot_{}", hex::encode(&rand::random::<[u8; 4]>())),
            name: label.to_string(),
            locator,
            wrapped_vmk,
            enrolled_at: chrono::Utc::now().to_rfc3339(),
        }],
        payload,
        version: 1,
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    let json_bytes = serde_json::to_vec_pretty(&capsule)
        .map_err(|e| format!("Failed to serialize capsule: {}", e))?;
    write_secure_file(path, &json_bytes)?;

    if !quiet {
        eprintln!("[✓] Initialized new vault capsule at {:?}", path);
    }
    Ok(())
}

fn cmd_get(
    path: &Path,
    query: &str,
    field: FieldType,
    as_json: bool,
    dev_mode: bool,
    key_arg: Option<&str>,
) -> Result<(), String> {
    let capsule = load_capsule_from_disk(path)?;
    let prf_secret = resolve_prf_key(dev_mode, key_arg);
    let (_vmk, entries) = unlock_capsule(&capsule, &prf_secret)?;

    let q_lower = query.to_lowercase();
    let matched = entries.iter().find(|e| {
        e.title.to_lowercase() == q_lower
            || e.domain.to_lowercase() == q_lower
            || e.title.to_lowercase().contains(&q_lower)
            || e.domain.to_lowercase().contains(&q_lower)
    });

    match matched {
        Some(e) => {
            if as_json {
                println!("{}", serde_json::to_string_pretty(e).unwrap());
                return Ok(());
            }
            match field {
                FieldType::Password => println!("{}", e.password),
                FieldType::Username => println!("{}", e.username),
                FieldType::Domain => println!("{}", e.domain),
                FieldType::Title => println!("{}", e.title),
                FieldType::Notes => println!("{}", e.notes),
                FieldType::All => {
                    println!("Title:    {}", e.title);
                    if !e.domain.is_empty() {
                        println!("Domain:   {}", e.domain);
                    }
                    if !e.username.is_empty() {
                        println!("Username: {}", e.username);
                    }
                    println!("Password: {}", e.password);
                    if !e.notes.is_empty() {
                        println!("Notes:    {}", e.notes);
                    }
                }
            }
            Ok(())
        }
        None => Err(format!("No secret found matching '{}'", query)),
    }
}

fn cmd_list(
    path: &Path,
    filter_opt: Option<&str>,
    as_json: bool,
    dev_mode: bool,
    key_arg: Option<&str>,
) -> Result<(), String> {
    let capsule = load_capsule_from_disk(path)?;
    let prf_secret = resolve_prf_key(dev_mode, key_arg);
    let (_vmk, entries) = unlock_capsule(&capsule, &prf_secret)?;

    let filtered: Vec<&VaultEntry> = if let Some(q) = filter_opt {
        let q_lower = q.to_lowercase();
        entries
            .iter()
            .filter(|e| {
                e.title.to_lowercase().contains(&q_lower)
                    || e.domain.to_lowercase().contains(&q_lower)
                    || e.username.to_lowercase().contains(&q_lower)
            })
            .collect()
    } else {
        entries.iter().collect()
    };

    if as_json {
        println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
        return Ok(());
    }

    if filtered.is_empty() {
        eprintln!("Vault is empty or no secrets matched query.");
        return Ok(());
    }

    let mut tw = TabWriter::new(io::stdout());
    writeln!(tw, "TITLE\tDOMAIN\tUSERNAME\tUPDATED").unwrap();
    writeln!(tw, "-----\t------\t--------\t-------").unwrap();
    for e in filtered {
        let date_short = e.updated_at.split('T').next().unwrap_or(&e.updated_at);
        writeln!(
            tw,
            "{}\t{}\t{}\t{}",
            e.title, e.domain, e.username, date_short
        )
        .unwrap();
    }
    tw.flush().map_err(|e| e.to_string())?;
    Ok(())
}

async fn cmd_add(
    path: &Path,
    title: &str,
    domain: Option<String>,
    username: Option<String>,
    password_opt: Option<String>,
    gen_pass: bool,
    length: usize,
    no_symbols: bool,
    notes: Option<String>,
    no_sync: bool,
    server_url: &str,
    dev_mode: bool,
    key_arg: Option<&str>,
    quiet: bool,
) -> Result<(), String> {
    if password_opt.is_some() {
        return Err(
            "Security Guard: Passing passwords via CLI flags is disabled to prevent credential leakage to shell history (~/.bash_history) and process listings (ps aux).\nRun without '-p' to enter the password manually via secure prompt, or use '-g' to auto-generate."
                .to_string(),
        );
    }

    let mut capsule = load_capsule_from_disk(path)?;
    let prf_secret = resolve_prf_key(dev_mode, key_arg);
    let (vmk, mut entries) = unlock_capsule(&capsule, &prf_secret)?;

    let pass = if gen_pass {
        let generated = generate_secure_password(length, no_symbols);
        if !quiet {
            eprintln!("[✓] Generated secure password: {}", generated);
        }
        generated
    } else if io::stdin().is_terminal() {
        eprint!("Enter password (leave empty to generate): ");
        let _ = io::stderr().flush();
        let input = rpassword::read_password().map_err(|e| e.to_string())?;
        if input.trim().is_empty() {
            let generated = generate_secure_password(length, no_symbols);
            if !quiet {
                eprintln!("[✓] Generated secure password: {}", generated);
            }
            generated
        } else {
            eprint!("Confirm password: ");
            let _ = io::stderr().flush();
            let confirm = rpassword::read_password().map_err(|e| e.to_string())?;
            if input != confirm {
                return Err("Error: Passwords do not match.".to_string());
            }
            input
        }
    } else {
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("Failed to read password from stdin: {}", e))?;
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_string();
        if trimmed.is_empty() {
            let generated = generate_secure_password(length, no_symbols);
            if !quiet {
                eprintln!("[✓] Generated secure password: {}", generated);
            }
            generated
        } else {
            trimmed
        }
    };

    let user = username.unwrap_or_default();
    let dom = domain.unwrap_or_default();
    let not = notes.unwrap_or_default();

    // Check if existing entry should be updated
    if let Some(existing) = entries.iter_mut().find(|e| e.title == title) {
        existing.domain = dom;
        existing.username = user;
        existing.password = pass;
        existing.notes = not;
        existing.updated_at = chrono::Utc::now().to_rfc3339();
        if !quiet {
            eprintln!("[✓] Updated existing credential '{}'", title);
        }
    } else {
        entries.push(VaultEntry {
            id: format!("sec_{}", hex::encode(&rand::random::<[u8; 6]>())),
            title: title.to_string(),
            domain: dom,
            username: user,
            password: pass,
            notes: not,
            updated_at: chrono::Utc::now().to_rfc3339(),
        });
        if !quiet {
            eprintln!("[✓] Added secret '{}'", title);
        }
    }

    capsule.payload = encrypt_entries(&entries, &vmk)?;
    capsule.version += 1;
    capsule.updated_at = chrono::Utc::now().to_rfc3339();

    let json_bytes = serde_json::to_vec_pretty(&capsule)
        .map_err(|e| format!("Failed to serialize capsule: {}", e))?;
    write_secure_file(path, &json_bytes)?;

    if !no_sync && !capsule.key_slots.is_empty() {
        let locator = &capsule.key_slots[0].locator;
        let client = VaultClient::new(server_url.to_string());
        match client.push_vault(locator, capsule.version, &capsule).await {
            Ok(_) => {
                if !quiet {
                    eprintln!("[✓] Synced update to remote server (v{})", capsule.version);
                }
            }
            Err(e) => {
                if !quiet {
                    eprintln!("[!] Note: Remote sync deferred ({})", e);
                }
            }
        }
    }

    Ok(())
}

async fn cmd_rm(
    path: &Path,
    query: &str,
    yes: bool,
    no_sync: bool,
    server_url: &str,
    dev_mode: bool,
    key_arg: Option<&str>,
    quiet: bool,
) -> Result<(), String> {
    let mut capsule = load_capsule_from_disk(path)?;
    let prf_secret = resolve_prf_key(dev_mode, key_arg);
    let (vmk, mut entries) = unlock_capsule(&capsule, &prf_secret)?;

    let q_lower = query.to_lowercase();
    let idx = entries.iter().position(|e| {
        e.title.to_lowercase() == q_lower || e.domain.to_lowercase() == q_lower
    });

    let idx = match idx {
        Some(i) => i,
        None => return Err(format!("No secret found matching '{}'", query)),
    };

    let title_to_remove = entries[idx].title.clone();
    if !yes {
        eprint!("Are you sure you want to delete '{}'? [y/N]: ", title_to_remove);
        let _ = io::stderr().flush();
        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        if input.trim().to_lowercase() != "y" && input.trim().to_lowercase() != "yes" {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    entries.remove(idx);
    capsule.payload = encrypt_entries(&entries, &vmk)?;
    capsule.version += 1;
    capsule.updated_at = chrono::Utc::now().to_rfc3339();

    let json_bytes = serde_json::to_vec_pretty(&capsule)
        .map_err(|e| format!("Failed to serialize capsule: {}", e))?;
    write_secure_file(path, &json_bytes)?;

    if !quiet {
        eprintln!("[✓] Deleted secret '{}'", title_to_remove);
    }

    if !no_sync && !capsule.key_slots.is_empty() {
        let locator = &capsule.key_slots[0].locator;
        let client = VaultClient::new(server_url.to_string());
        let _ = client.push_vault(locator, capsule.version, &capsule).await;
    }

    Ok(())
}

async fn cmd_sync(
    path: &Path,
    server_url: &str,
    _dev_mode: bool,
    _key_arg: Option<&str>,
    quiet: bool,
) -> Result<(), String> {
    let local_capsule = load_capsule_from_disk(path)?;
    if local_capsule.key_slots.is_empty() {
        return Err("No key slots found in local capsule.".to_string());
    }

    let locator = &local_capsule.key_slots[0].locator;
    let client = VaultClient::new(server_url.to_string());

    if !quiet {
        eprintln!("[*] Syncing with relay server at {}...", server_url);
    }

    let remote_res = client.pull_vault(locator).await?;
    match remote_res {
        Some(remote) => {
            if remote.version > local_capsule.version {
                if !quiet {
                    eprintln!(
                        "[*] Remote has newer version ({} > {}). Updating local...",
                        remote.version, local_capsule.version
                    );
                }
                let json_bytes = serde_json::to_vec_pretty(&remote.capsule)
                    .map_err(|e| format!("Failed to serialize capsule: {}", e))?;
                write_secure_file(path, &json_bytes)?;
                if !quiet {
                    eprintln!("[✓] Local capsule updated to v{}", remote.version);
                }
            } else if local_capsule.version > remote.version {
                if !quiet {
                    eprintln!(
                        "[*] Local has newer version ({} > {}). Pushing to server...",
                        local_capsule.version, remote.version
                    );
                }
                client
                    .push_vault(locator, local_capsule.version, &local_capsule)
                    .await?;
                if !quiet {
                    eprintln!("[✓] Remote updated to v{}", local_capsule.version);
                }
            } else {
                if !quiet {
                    eprintln!("[✓] Local and remote are synchronized at version {}", local_capsule.version);
                }
            }
        }
        None => {
            if !quiet {
                eprintln!("[*] Server has no existing record for this vault. Registering...");
            }
            client
                .push_vault(locator, local_capsule.version, &local_capsule)
                .await?;
            if !quiet {
                eprintln!("[✓] Pushed local vault to server (v{})", local_capsule.version);
            }
        }
    }
    Ok(())
}

async fn cmd_pull(path: &Path, server_url: &str, quiet: bool) -> Result<(), String> {
    let local_capsule = load_capsule_from_disk(path)?;
    if local_capsule.key_slots.is_empty() {
        return Err("No key slots found in local capsule.".to_string());
    }

    let locator = &local_capsule.key_slots[0].locator;
    let client = VaultClient::new(server_url.to_string());

    let remote = client
        .pull_vault(locator)
        .await?
        .ok_or_else(|| "No remote vault found for this locator".to_string())?;

    let json_bytes = serde_json::to_vec_pretty(&remote.capsule)
        .map_err(|e| format!("Failed to serialize capsule: {}", e))?;
    write_secure_file(path, &json_bytes)?;

    if !quiet {
        eprintln!("[✓] Pulled version {} from server into {:?}", remote.version, path);
    }
    Ok(())
}

async fn cmd_push(path: &Path, server_url: &str, quiet: bool) -> Result<(), String> {
    let local_capsule = load_capsule_from_disk(path)?;
    if local_capsule.key_slots.is_empty() {
        return Err("No key slots found in local capsule.".to_string());
    }

    let locator = &local_capsule.key_slots[0].locator;
    let client = VaultClient::new(server_url.to_string());

    client
        .push_vault(locator, local_capsule.version, &local_capsule)
        .await?;

    if !quiet {
        eprintln!("[✓] Pushed local version {} to server", local_capsule.version);
    }
    Ok(())
}

fn cmd_import(path: &Path, import_path: &Path, quiet: bool) -> Result<(), String> {
    if !import_path.exists() {
        return Err(format!("Import file does not exist: {:?}", import_path));
    }
    let data = fs::read_to_string(import_path)
        .map_err(|e| format!("Failed to read import file: {}", e))?;

    // Try parsing as raw capsule or backup envelope
    let capsule: VaultCapsule = if let Ok(c) = serde_json::from_str::<VaultCapsule>(&data) {
        c
    } else if let Ok(val) = serde_json::from_str::<serde_json::Value>(&data) {
        if let Some(c_val) = val.get("capsule") {
            serde_json::from_value::<VaultCapsule>(c_val.clone())
                .map_err(|e| format!("Failed to parse nested capsule: {}", e))?
        } else {
            return Err("Invalid backup file: missing 'capsule' field".to_string());
        }
    } else {
        return Err("Failed to parse JSON in import file".to_string());
    };

    let json_bytes = serde_json::to_vec_pretty(&capsule)
        .map_err(|e| format!("Failed to serialize capsule: {}", e))?;
    write_secure_file(path, &json_bytes)?;

    if !quiet {
        eprintln!(
            "[✓] Successfully imported vault capsule (v{}) into {:?}",
            capsule.version, path
        );
    }
    Ok(())
}

fn cmd_export(path: &Path, out_opt: Option<&Path>, quiet: bool) -> Result<(), String> {
    let capsule = load_capsule_from_disk(path)?;
    let backup_obj = serde_json::json!({
        "format": "voidvault-capsule-v2",
        "exportedAt": chrono::Utc::now().to_rfc3339(),
        "version": capsule.version,
        "capsule": capsule
    });

    let json = serde_json::to_string_pretty(&backup_obj)
        .map_err(|e| format!("Failed to serialize export: {}", e))?;

    if let Some(out) = out_opt {
        write_secure_file(out, json.as_bytes())?;
        if !quiet {
            eprintln!("[✓] Exported encrypted backup to {:?}", out);
        }
    } else {
        println!("{}", json);
    }
    Ok(())
}

fn cmd_config(action: ConfigAction) -> Result<(), String> {
    let mut cfg = load_config();
    match action {
        ConfigAction::Show => {
            println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
        }
        ConfigAction::Get { key } => match key.as_str() {
            "server" | "server_url" => println!("{}", cfg.server_url.as_deref().unwrap_or("none")),
            "mode" => println!("{}", cfg.mode.as_deref().unwrap_or("local")),
            "credential_id" => {
                println!("{}", cfg.default_credential_id.as_deref().unwrap_or("none"))
            }
            _ => return Err(format!("Unknown configuration key: '{}'", key)),
        },
        ConfigAction::Set { key, value } => {
            match key.as_str() {
                "server" | "server_url" => cfg.server_url = Some(value),
                "mode" => {
                    if value != "local" && value != "remote" {
                        return Err("Mode must be 'local' or 'remote'".to_string());
                    }
                    cfg.mode = Some(value);
                }
                "credential_id" => cfg.default_credential_id = Some(value),
                _ => return Err(format!("Unknown configuration key: '{}'", key)),
            }
            save_config(&cfg)?;
            eprintln!("[✓] Config updated.");
        }
    }
    Ok(())
}

async fn cmd_status(path: &Path, server_url: &str) -> Result<(), String> {
    println!("VoidVault CLI v0.2.0 (Stateless Engine)");
    println!("Capsule Path: {:?}", path);

    if path.exists() {
        if let Ok(capsule) = load_capsule_from_disk(path) {
            println!("Local Version: {}", capsule.version);
            println!("Key Slots:     {}", capsule.key_slots.len());
            for (i, slot) in capsule.key_slots.iter().enumerate() {
                println!(
                    "  [{}] {} (locator: {}...)",
                    i,
                    slot.name,
                    &slot.locator[..12.min(slot.locator.len())]
                );
            }
        } else {
            println!("Capsule:       [Corrupted / Unreadable]");
        }
    } else {
        println!("Capsule:       [Not initialized]");
    }

    println!("Server URL:    {}", server_url);
    let client = VaultClient::new(server_url.to_string());
    match client.check_health().await {
        Ok(h) => println!("Server Status: Online ({})", h),
        Err(e) => println!("Server Status: Offline ({})", e),
    }

    Ok(())
}

fn generate_secure_password(length: usize, no_symbols: bool) -> String {
    use rand::Rng;
    let chars: &[u8] = if no_symbols {
        b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    } else {
        b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*+?"
    };

    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..chars.len());
            chars[idx] as char
        })
        .collect()
}
