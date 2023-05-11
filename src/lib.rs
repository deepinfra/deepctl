pub mod docker {

    use std::io::Write;
    use anyhow::{Result, Context, Error};

    const DEEPINFRA_REGISTRY: &str = "registry.deepinfra.com";

    // inspired by https://github.com/moby/moby/tree/master/pkg/homedir
    fn home_dir() -> Option<std::path::PathBuf> {
        // the dirs crate uses different windows home
        if cfg!(target_family = "windows") {
            std::env::var("USERPROFILE").ok().map(std::path::PathBuf::from)
        } else if cfg!(target_family = "unix") {
            std::env::var("HOME").ok().map(std::path::PathBuf::from)
        } else {
            None
        }
    }

    // inspired by https://github.com/docker/cli/blob/master/cli/config/credentials
    fn config_path() -> Result<std::path::PathBuf> {
        if let Ok(docker_config) = std::env::var("DOCKER_CONFIG") {
            Ok(docker_config.into())
        } else {
            home_dir().map(|f| f.join(".docker").join("config.json"))
                .ok_or(Error::msg("can't figure out docker config path"))
        }
    }

    // fn platform_cred_store() -> Option<String> {
    //     if cfg!(target_os = "windows") {
    //         Some("wincred".to_owned())
    //     } else if cfg!(target_os = "macos") {
    //         Some("osxkeychain".to_owned())
    //     } else if cfg!(target_family = "unix") {
    //         // this is the logic from https://github.com/docker/cli/blob/master/cli/config/credentials/default_store_linux.go
    //         // which is obviously wrong (i.e if you have both + one docker-credential-secretstore it won't use it)
    //         if let Ok(pass_path) = which::which("pass") {
    //             Some("pass".to_owned())
    //         } else {
    //             Some("secretstore".to_owned())
    //         }
    //     } else {
    //         None
    //     }
    // }

    fn dc_full(native: &str) -> String {
        format!("docker-credential-{}", native)
    }

    // fn active_cred_store() -> Option<std::path::PathBuf> {
    //     platform_cred_store()
    //         .and_then(|native| which::which(dc_full(&native)).ok())
    // }

    fn store_credstore(creds_store: &str, user: &str, pass: &str) -> Result<()> {
        use std::process::{Command, Stdio};
        use serde_json::json;

        let helper = dc_full(creds_store);
        let helper_path = which::which(&helper)
            .with_context(|| format!("can't find docker credstore helper for {}", &creds_store))?;
        let mut cmd = Command::new(helper_path)
            .arg("store")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let payload = json!({
            "Username": user,
            "Secret": pass,
            "ServerURL": "registry.deepinfra.com"
        }).to_string();
        {
            let stdin = cmd.stdin.as_mut()
                .ok_or(Error::msg(format!("failed to communicate with {:?}", helper)))?;
            stdin.write_all(payload.as_bytes())?;
        }
        let res = cmd.wait()?;
        if res.success() {
            Ok(())
        } else {
            Err(Error::msg(format!("{:?} failed: {}", helper, res.to_string())))
        }
    }

    fn load_docker_config() -> Result<serde_json::Value> {
        let path = config_path()?;
        let file = std::fs::File::open(path)?;
        Ok(serde_json::from_reader(file)?)
    }

    fn store_docker_config(payload: &serde_json::Value) -> Result<()> {
        let path = config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::File::create(&path)
            .with_context(|| format!("failed to write {:?}", &path))?;
        Ok(serde_json::to_writer_pretty(file, payload)?)
    }

    fn serialize_auth(user: &str, pass: &str) -> String {
        let raw = format!("{}:{}", user, pass);
        base64::encode(raw)
    }

    fn insert_cred(cfg: &mut serde_json::Value, user: &str, pass: &str) -> Result<()> {
        use serde_json::json;
        if !cfg.is_object() {
            *cfg = json!({});
        }
        let top = cfg.as_object_mut()
            .ok_or(Error::msg("can't access root docker config obj"))?;
        let auths_state = top.get("auths").map(|auths| auths.is_object());
        if auths_state == None || auths_state == Some(false) {
            top.insert("auths".to_owned(), json!({}));
        }
        let auths = top
            .get_mut("auths")
            .and_then(|a| a.as_object_mut())
            .ok_or(Error::msg("can't access .auths object"))?;
        // drop alternative registry spellings
        auths.remove(&format!("http://{}", DEEPINFRA_REGISTRY));
        auths.remove(&format!("https://{}", DEEPINFRA_REGISTRY));
        auths.insert(DEEPINFRA_REGISTRY.to_owned(), json!({
            "auth": serialize_auth(user, pass)
        }));
        Ok(())
    }

    fn store_plain(user: &str, pass: &str) -> Result<()> {
        use serde_json::json;
        let mut cfg = load_docker_config()
            .or::<Error>(Ok(json!({})))?;
        insert_cred(&mut cfg, user, pass)?;
        Ok(store_docker_config(&cfg)?)
    }

    pub fn store_creds(user: &str, pass: &str) -> Result<()> {
        if let Ok(cfg) = load_docker_config() {
            if let Some(creds_store) = cfg.get("credsStore").and_then(|cs| cs.as_str()) {
                return store_credstore(creds_store, user, pass);
            }
        }
        store_plain(user, pass)
    }

}