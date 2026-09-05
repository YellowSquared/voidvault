use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub default_credential_id: Option<String>,
    #[serde(default)]
    pub mode: Option<String>, // "local" or "remote"
}

pub fn get_default_config_dir() -> PathBuf {
    if let Ok(val) = std::env::var("VOIDVAULT_CONFIG_DIR") {
        PathBuf::from(val)
    } else if let Some(dir) = dirs::config_dir() {
        dir.join("voidvault")
    } else {
        PathBuf::from(".voidvault")
    }
}

pub fn get_default_capsule_path() -> PathBuf {
    if let Ok(val) = std::env::var("VOIDVAULT_FILE") {
        PathBuf::from(val)
    } else {
        get_default_config_dir().join("vault.capsule")
    }
}

pub fn get_default_config_file() -> PathBuf {
    get_default_config_dir().join("config.json")
}

pub fn ensure_config_dir() -> Result<PathBuf, String> {
    let dir = get_default_config_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create config dir {:?}: {}", dir, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(dir)
}

pub fn load_config() -> AppConfig {
    let file = get_default_config_file();
    if file.exists() {
        if let Ok(content) = fs::read_to_string(&file) {
            if let Ok(cfg) = serde_json::from_str::<AppConfig>(&content) {
                return cfg;
            }
        }
    }
    AppConfig::default()
}

pub fn save_config(cfg: &AppConfig) -> Result<(), String> {
    ensure_config_dir()?;
    let file = get_default_config_file();
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(&file, json).map_err(|e| format!("Failed to write config file {:?}: {}", file, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&file, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn write_secure_file(path: &Path, content: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create parent directory {:?}: {}", parent, e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
    }

    fs::write(path, content).map_err(|e| format!("Failed to write to file {:?}: {}", path, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}
