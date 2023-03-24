use anyhow::{Result, Context};
use clap::{Parser, Subcommand, ValueEnum};
use dirs;
use reqwest::blocking::multipart;
use reqwest::{self, Method};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::process::exit;
use thiserror::Error;
use version_compare::Version;
use webbrowser;
use base64;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const DEEPINFRA_LOGIN_HOST_PROD: &str = "https://deepinfra.com";
const DEEPINFRA_HOST_PROD: &str = "https://api.deepinfra.com";
const DEEPINFRA_HOST_DEV: &str = "https://localhost:7001";
const LOGIN_PATH_PROD: &str = "/signup/";
const LOGIN_PATH_DEV: &str = "/github/login";
const VERSION_CHECK_SEC: i64 = 60 * 60 * 24 * 7; // 1 week
const GITHUB_RELEASE_LATEST: &str = "https://github.com/deepinfra/deepctl/releases/latest/download";

#[derive(Error, Debug)]
pub enum DeepCtlError {
    #[error("You need to log in first")]
    NotLoggedIn(#[from] anyhow::Error),
    #[error("Invalid configuration file")]
    BadConfig,
    #[error("Can't figure out {0} from environment")]
    BadEnv(&'static str),
    #[error("backend returned wrong/unexpected object: {0}")]
    ApiMismatch(String),
    #[error("something looks wrong on your end: {0}")]
    BadInput(String),
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct VersionData {
    min: String,
    update: String,
    latest: String,
    last_check: i64
}

#[derive(Parser)]
#[command(author, version)]
#[command(about = "deepctl is a command line interface to the Deep Infra inference platform.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long)]
    /// use dev host
    dev: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Authentication commands for Deep Infra
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// model deployment commands
    Deploy {
        /// deploys a model
        #[command(subcommand)]
        command: DeployCommands,
    },
    /// model commands
    Model {
        #[command(subcommand)]
        command: ModelCommands,
    },
    /// inference command
    Infer {
        /// model name
        #[arg(short, long)]
        model: String,
        /// inference arguments (eg. -i k=v -i k2=v2)
        #[arg(short('i'), value_parser = infer_args_parser)]
        args: Vec<(String, String)>,
        /// inference output (eg. -i images=dir/image.{IDX}.{EXT})
        #[arg(short('o'), value_parser = infer_out_parser)]
        outputs: Vec<(String, String)>,
    },
    /// version command
    Version {
        #[command(subcommand)]
        command: VersionSubcommands,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// login to Deep Infra
    Login,
    /// logout of Deep Infra
    Logout,
    /// print the current API token
    Token,
}

#[derive(Subcommand)]
enum DeployCommands {
    /// deploy a new model
    Create {
        /// The model name (e.g microsoft/resnet-50)
        #[arg(short, long)]
        model: String,
        /// The model task (optional)
        #[arg(short, long)]
        task: Option<ModelTask>,
    },
    /// list deployed models
    List {
        /// show only deploys in given state
        #[arg(long, value_enum, default_value_t=DeployState::ACTIVE)]
        state: DeployState,
    },
    /// get information on a particular deployment
    Info { deploy_id: String },
    /// remove a deploymnet
    Delete { deploy_id: String },
}

#[derive(Serialize, Deserialize, ValueEnum, Eq, PartialEq, Clone, Debug)]
#[serde(rename_all="kebab-case")]
enum ModelTask {
    AutomaticSpeechRecognition,
    Embeddings,
    FillMask,
    ImageClassification,
    ObjectDetection,
    QuestionAnswering,
    Text2textGeneration,
    TextClassification,
    TextGeneration,
    TextToImage,
    TokenClassification,
    ZeroShotImageClassification,
}

#[derive(Subcommand)]
enum ModelCommands {
    /// list models
    List,
    /// get model info
    Info {
        /// model name
        #[arg(short('m'), long)]
        model: String,
    },
}

#[derive(Subcommand)]
enum TestSubcommands {
    /// test command1
    Command1,
    /// test command2
    Command2,
    /// check cli version
    Version,
}

#[derive(Subcommand)]
enum VersionSubcommands {
    /// check for newer version
    Check,
    /// self update to latest version
    Update,
}

/// deploy state
#[derive(ValueEnum, Eq, PartialEq, Hash, Clone, Debug)]
enum DeployState {
    /// any state
    ANY,
    /// initializing, deploying or running
    ACTIVE,
    /// failed or deleted
    INACTIVE,
    /// initializing or deploying
    PENDING,
    INITIALIZING,
    DEPLOYING,
    RUNNING,
    FAILED,
    DELETED,
}

fn random_string(len: usize) -> String {
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

// TODO: Ensure query/path is properly encoded (use reqwest::Url)
fn get_response_extra<BM>(
    path: &str,
    method: Method,
    dev: bool,
    auth: bool,
    builder_map: BM,
) -> Result<reqwest::blocking::Response>
where
    BM: FnOnce(reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder,
{
    let client = get_http_client(dev)?;
    let host = get_host(dev);
    let mut rb = client.request(method, format!("{}{}", host, path));

    if auth {
        let access_token = get_access_token(dev).map_err(DeepCtlError::NotLoggedIn)?;
        rb = rb.bearer_auth(access_token);
    }

    rb = builder_map(rb);

    Ok(rb.send()?)
}

fn get_response(
    path: &str,
    method: Method,
    dev: bool,
    auth: bool,
) -> Result<reqwest::blocking::Response> {
    get_response_extra(path, method, dev, auth, |rb| rb)
}

fn get_parsed_response_extra<BM>(
    path: &str,
    method: Method,
    dev: bool,
    auth: bool,
    builder_map: BM,
) -> Result<serde_json::Value>
where
    BM: FnOnce(reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder,
{
    let result = get_response_extra(path, method, dev, auth, builder_map)?.error_for_status()?;
    let body = result.text()?;
    Ok(serde_json::from_str(&body)?)
}

fn get_parsed_response(
    path: &str,
    method: Method,
    dev: bool,
    auth: bool,
) -> Result<serde_json::Value> {
    get_parsed_response_extra(path, method, dev, auth, |rb| rb)
}

#[derive(Serialize, Deserialize)]
struct ConfigData {
    access_token: String
}

fn auth_login(dev: bool) -> Result<()> {
    println!("auth login");
    let login_id = random_string(32);
    let (host, path) = match dev {
        true => (DEEPINFRA_HOST_DEV, LOGIN_PATH_DEV),
        false => (DEEPINFRA_LOGIN_HOST_PROD, LOGIN_PATH_PROD),
    };
    let login_url = format!("{}{}?login_id={}", host, path, login_id);
    println!("opening login url: {}", login_url);
    if webbrowser::open(&login_url).is_ok() {
        println!("Opened login page. Please follow instructions in your browser.");
        println!("Waiting for login to complete");
        let json = get_parsed_response_extra(
            &format!("/github/cli/login?login_id={}", login_id),
            Method::GET,
            dev,
            false,
            |rb| rb.timeout(std::time::Duration::from_secs(300)),
        ).context("waiting for auth result from backend")?;
        let token = json.get("access_token")
            .and_then(|v| v.as_str())
            .ok_or(DeepCtlError::ApiMismatch("login should return access_token".into()))?;

        write_config(&ConfigData { access_token: token.into() }, dev)?;
        println!("login successful");
        Ok(())
    } else {
        println!("failed to open login page");
        exit(1)
    }
}

fn read_config(dev: bool) -> Result<ConfigData> {
    let config_path = get_config_path(dev)?;
    let file = File::open(config_path)?;
    Ok(serde_yaml::from_reader(file)?)
}

fn get_access_token(dev: bool) -> Result<String> {
    Ok(read_config(dev)?.access_token)
}

fn write_config(config_data: &ConfigData, dev: bool) -> Result<()> {
    let config_path = get_config_path(dev)?;
    // config_path always has a parent
    fs::create_dir_all(&config_path.parent().unwrap())?;
    let file = File::create(config_path)?;
    serde_yaml::to_writer(file, config_data)?;
    Ok(())
}

fn get_di_dir() -> Result<std::path::PathBuf> {
    Ok(dirs::home_dir()
        .ok_or(DeepCtlError::BadEnv("home_dir"))?
        .join(".deepinfra"))
}

fn get_config_path(dev: bool) -> Result<std::path::PathBuf> {
    Ok(get_di_dir()?
        .join(if dev {
            "config_dev.yaml"
        } else {
            "config.yaml"
        }))
}

fn get_version_path() -> Result<std::path::PathBuf> {
    Ok(get_di_dir()?.join("version.yaml"))
}

fn read_version_data() -> Result<VersionData> {
    let config_path = get_version_path()?;
    let file = File::open(&config_path)?;
    Ok(serde_yaml::from_reader(file)?)
}

fn auth_logout(_dev: bool) -> Result<()> {
    // TODO: send request to the backend to let the backend know that the token is no longer valid
    let config_path = get_config_path(_dev)?;
    fs::remove_file(config_path)?;
    println!("logout done");
    Ok(())
}

fn auth_token(dev: bool) -> Result<()> {
    let access_token = get_access_token(dev)
        .map_err(DeepCtlError::NotLoggedIn)?;
    println!("{}", access_token);
    Ok(())
}

fn get_http_client(dev: bool) -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(dev)
        .build()?)
}

fn models_list(dev: bool) -> Result<()> {
    let json = get_parsed_response("/models/list", Method::GET, dev, true)?;
    let mut models = json
        .as_array()
        .ok_or(DeepCtlError::ApiMismatch("/models/list doesn't contain a models array".into()))?
        .iter()
        .filter_map(|model| {
            if let (Some(m_type), Some(model_name)) = (
                    model.get("type").and_then(|prop| prop.as_str()),
                    model.get("model_name").and_then(|prop| prop.as_str())) {
                Some((m_type, model_name))
            } else {
                None
            }
        })
        .collect::<Vec<(&str, &str)>>();

    models.sort();

    models.iter().for_each(|(m_type, model_name)| {
        println!("{}: {}", m_type, model_name);
    });
    Ok(())
}

fn model_info(model: &str, dev: bool) -> Result<()> {
    let json = get_parsed_response(&format!("/models/{}", model), Method::GET, dev, false)?;

    fn get_str<'a>(json: &'a serde_json::Value, key: &str) -> Result<&'a str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .ok_or(DeepCtlError::ApiMismatch(format!("model info should contain {} of type string", key)).into())
    }

    // println!("{:?}", json);
    println!("model: {}", model);
    println!("type: {}", get_str(&json, "type")?);
    if let Ok(mask_token) = get_str(&json, "mask_token") {
        println!("mask token: {}", mask_token);
    }
    println!(
        "CURL invocation:\n\n {}\n",
        get_str(&json, "curl_inv")?
    );
    println!(
        "deepctl invocation:\n\n {}\n",
        get_str(&json, "cmdline_inv")?
    );
    println!(
        "Field description:\n\n{}\n",
        get_str(&json, "txt_docs")?
    );
    println!(
        "output example:\n\n{}\n",
        get_str(&json, "out_example")?
    );
    println!(
        "output fields description:\n\n{}\n",
        get_str(&json, "out_docs")?
    );

    Ok(())
}

fn get_host(dev: bool) -> String {
    let host = match env::var("DEEPINFRA_HOST") {
        Ok(val) => val,
        Err(_) => match dev {
            true => DEEPINFRA_HOST_DEV.to_string(),
            false => DEEPINFRA_HOST_PROD.to_string(),
        },
    };
    host
}

fn deploy_list(dev: bool, state: DeployState) -> Result<()> {
    let json = get_parsed_response("/deploy/list/", Method::GET, dev, true)?;
    let allowed_statuses = match state {
        DeployState::ACTIVE => vec!["initializing", "deploying", "running"],
        DeployState::INACTIVE => vec!["failed", "deleted"],
        DeployState::PENDING => vec!["initializing", "deploying"],
        DeployState::ANY => vec!["initializing", "deploying", "running", "failed", "deleted"],
        DeployState::INITIALIZING => vec!["initializing"],
        DeployState::DEPLOYING => vec!["deploying"],
        DeployState::RUNNING => vec!["running"],
        DeployState::FAILED => vec!["failed"],
        DeployState::DELETED => vec!["deleted"],
    };
    let deploys: Vec<&serde_json::Value> = json.as_array()
        .ok_or(DeepCtlError::ApiMismatch("/delpoy/list/ result is not an array".into()))?
        .iter()
        .filter(|d| {
            let status = d.get("status").and_then(|s| s.as_str());
            status.is_some() && allowed_statuses.contains(&status.unwrap())
        })
        .collect();
    // deploys was parsed from json and filtered, so it can't fail
    println!("{}", serde_json::to_string_pretty(&deploys).unwrap());
    Ok(())
}

fn deploy_info(deploy_id: &str, dev: bool) -> Result<()> {
    let json = get_parsed_response(&format!("/deploy/{}", deploy_id), Method::GET, dev, true)?;
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

fn deploy_delete(deploy_id: &str, dev: bool) -> Result<()> {
    get_response(&format!("/deploy/{}", deploy_id), Method::DELETE, dev, true)?
        .error_for_status()?;
    Ok(())
}

fn deploy_create(model_name: &str, task: Option<&ModelTask>, dev: bool) -> Result<()> {
    let body = {
        let mut params = serde_json::Map::new();
        params.insert("model_name".into(), model_name.into());
        if let Some(task) = task {
            params.insert("task".into(), serde_json::to_value(task).unwrap());
        };
        serde_json::to_string(&params)?
    };
    let json = get_parsed_response_extra("/deploy/hf/", Method::POST, dev, true, |rb| {
        rb.header("Content-type", "application/json").body(body)
    })?;

    let deploy_id = json.get("deploy_id")
        .and_then(|v| v.as_str())
        .ok_or(DeepCtlError::ApiMismatch("delpoy model response should contain deploy_id".into()))?;
    println!("deployed {} {:?} -> {}", model_name, &task, deploy_id);
    let mut last_status = String::new();
    loop {
        let tjson =
            get_parsed_response(&format!("/deploy/{}", &deploy_id), Method::GET, dev, true)?;
        let status = tjson.get("status")
            .and_then(serde_json::Value::as_str)
            .ok_or(DeepCtlError::ApiMismatch("deploy info response should contain status".into()))?;
        if status != last_status {
            // print the status replacing the last line
            eprintln!("status: {}", status);
            last_status = String::from(status);
        }
        if status == "initializing" || status == "deploying" {
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }
        // TODO: Non-zero exit status on failed (what about deleted, stopping)?
        println!("deployment {} --> {}", deploy_id, status);
        if status == "failed" {
            let error = tjson.get("fail_reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            eprintln!("error: {}", error);
        }
        break;
    }
    Ok(())
}

fn read_binary_file(name: &str) -> Result<Vec<u8>> {
    let mut file = File::open(name)?;
    let mut buf: Vec<u8> = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

fn parse_base64(b64: &str) -> Result<Vec<u8>> {
    Ok(base64::decode(b64)?)
}

fn infer_body(args: &Vec<(String, String)>) -> Result<multipart::Form> {
    let mut form = multipart::Form::new();
    for (key, inp_value) in args {
        let raw_value = if inp_value.starts_with("@") {
            read_binary_file(&inp_value[1..])?
        } else if inp_value.starts_with("base64:") {
            parse_base64(&inp_value[7..])?
        } else {
            inp_value.as_bytes().to_vec()
        };

        let mut part = multipart::Part::bytes(raw_value);
        // the filename forces the backend to treat this data as binary
        part = part.file_name("filename.ext");
        form = form.part(key.to_owned(), part);
    }

    Ok(form)
}

fn infer_out_part(value: &serde_json::Value, location: &str) -> Result<()> {
    use serde_json::Value;
    let accepts_json = |loc: &str| loc.ends_with(".json") || loc.eq("-");
    let json_type_str = |value: &Value| match value {
        Value::Null => "null",
        Value::Bool(_b) => "bool",
        Value::Number(_n) => "number",
        Value::String(_s) => "string",
        Value::Array(_a) => "array",
        Value::Object(_o) => "object",
    };
    fn mime_to_ext(mime: &str) -> Result<&'static str> {
        match mime {
            "image/png" => Ok("png"),
            _ => Err(DeepCtlError::ApiMismatch(format!("unexpected mime type {}", mime)).into()),
        }
    }
    fn create_file(location: &str) -> Result<std::fs::File> {
        let path = std::path::PathBuf::from(location);
        Ok(File::create(&path)
            .with_context(|| format!("failed to create {:?}", &path))?)
    }
    fn store_json(value: &Value, location: &str) -> Result<()> {
        if location != "-" {
            serde_json::to_writer_pretty(create_file(location)?, value)?;
        } else {
            serde_json::to_writer_pretty(&mut std::io::stdout(), value)?;
        };
        Ok(())
    }
    fn store_blob(data: &[u8], location: &str) -> Result<()> {
        create_file(location)?.write_all(data)?;
        Ok(())
    }
    fn parse_data_url(data_url: &str) -> Option<(&str, Vec<u8>)> {
        if data_url.starts_with("data:") {
            if let Some(semi) = data_url.find(";") {
                if data_url[semi+1..semi+8].eq("base64,") {
                    if let Ok(data) = base64::decode(&data_url[semi+8..]) {
                        return Some((&data_url[5..semi], data));
                    }
                    // TODO: If it looks like a data url, but doesn't decode we should probably raise an error
                }
            }
        }
        None
    }

    if let Value::Array(arr) = value {
        if location.contains("{IDX}") {
            for (idx, item) in arr.iter().enumerate() {
                infer_out_part(item, &location.replace("{IDX}", &idx.to_string()))?;
            }
            Ok(())
        } else if accepts_json(location) {
            // dump the whole thing
            store_json(value, location)
        } else if arr.len() == 1 {
            infer_out_part(arr.get(0).unwrap(), location)
        } else {
            Err(DeepCtlError::BadInput(format!("can't write arr(len={}) to {}", arr.len(), location)).into())
        }
    } else if let Value::String(str) = value {
        if let Some((mime, data)) = parse_data_url(str) {
            store_blob(&data, &location.replace("{EXT}", mime_to_ext(mime)?))
        } else if accepts_json(location) {
            store_json(value, location)
        } else {
            Err(DeepCtlError::BadInput(format!("can't write non-data-uri starting with {} string to {}", &str[..10], location)).into())
        }
    } else if accepts_json(location) {
        store_json(value, location)
    } else {
        Err(DeepCtlError::BadInput(format!("can't write type {} to {}", json_type_str(value), location)).into())
    }
}

fn infer(model_name: &str, args: &Vec<(String, String)>, outs: &Vec<(String, String)>, dev: bool) -> Result<()> {
    let form = infer_body(args)?;

    let json = get_parsed_response_extra(
        &format!("/v1/inference/{}", model_name),
        Method::POST,
        dev,
        true,
        move |rb| {
            rb.timeout(std::time::Duration::from_secs(1800))
                .multipart(form)
        },
    )?;

    let outs_default = &vec![("".to_owned(), "-".to_owned())];
    let outs = if outs.len() == 0 { outs_default } else { outs };
    for (path, target) in outs {
        let path_ptr = if path.is_empty() {
            "".to_owned()
        } else {
            format!("/{}", path.replace(".", "/"))
        };
        infer_out_part(
            json.pointer(&path_ptr)
                .ok_or(DeepCtlError::BadInput(format!("can't index with _{}_", path)))?,
            target)?;
    }
    Ok(())
}

fn infer_args_parser(s: &str) -> Result<(String, String), String> {
    if let Some(eq) = s.find('=') {
        Ok((s[..eq].to_owned(), s[eq+1..].to_owned()))
    } else {
        Err("Invalid argument format. Expected key=value".into())
    }
}

fn infer_out_parser(s: &str) -> Result<(String, String), String> {
    if let Some(eq) = s.find('=') {
        Ok((s[..eq].into(), s[eq+1..].into()))
    } else {
        Ok(("".into(), s.into()))
    }
}

fn check_version_with_server(dev: bool) -> Result<VersionData> {
    let now = unix_ts();
    let json = get_parsed_response(
        &format!("/cli/version?version={}", VERSION),
        Method::GET,
        dev,
        false,
    )?;
    fn get_str<'a>(json: &'a serde_json::Value, key: &str) -> Result<&'a str> {
        json.get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or(DeepCtlError::ApiMismatch(format!("version info should contain {} of type string", key)).into())
    }
    let min_version_str = get_str(&json, "min")?;
    let update_version_str = get_str(&json, "update")?;
    let latest_version_str = get_str(&json, "latest")?;
    let version_data = VersionData {
        min: min_version_str.into(),
        update: update_version_str.into(),
        latest: latest_version_str.into(),
        last_check: now,
    };

    write_version_data(&version_data)?;

    Ok(version_data)
}

fn unix_ts() -> i64 {
    use std::time::SystemTime;
    let now = SystemTime::now();
    if let Ok(unix_dur) = now.duration_since(SystemTime::UNIX_EPOCH) {
        unix_dur.as_secs() as i64
    } else if let Ok(unix_dur) = SystemTime::UNIX_EPOCH.duration_since(now) {
        - (unix_dur.as_secs() as i64)
    } else {
        0
    }
}

fn main_version_check(dev: bool, force: bool) -> Result<()> {
    let crnt_version_data: Option<VersionData> = read_version_data().ok();
    let latest_acceptable = unix_ts() - VERSION_CHECK_SEC;
    let version_data = if crnt_version_data.is_none()
        || force
        || crnt_version_data.as_ref().unwrap().last_check < latest_acceptable
    {
        println!("checking version with server...");
        check_version_with_server(dev)?
    } else {
        crnt_version_data.unwrap()
    };
    do_version_check(&version_data, true)?;
    Ok(())
}

fn prompt_update(reason: &str, latest: &str) {
    println!(
        "Your version {} is {}. Please update to the latest version {}.",
        VERSION, reason, latest
    );

    let mut sudo_str = "sudo ";
    if let (Ok(exe), Some(home_dir)) = (std::env::current_exe(), dirs::home_dir()) {
        if exe
            .as_path()
            .starts_with(home_dir.as_path())
        {
            sudo_str = "";
        }
    }
    println!(
        "Update to the latest version using `{}deepctl version update`",
        sudo_str
    );
}

fn do_version_check(version_data: &VersionData, silent: bool) -> Result<()> {
    fn ver_from_str(s: &str) -> Result<Version> {
        Ok(Version::from(s)
            .ok_or(DeepCtlError::ApiMismatch(format!("version string {} doesn't parse", s)))?)
    }

    let this_version = ver_from_str(VERSION)?;
    let min_version = ver_from_str(&version_data.min)?;
    let update_version = ver_from_str(&version_data.update)?;

    if this_version < min_version {
        prompt_update("too old", &version_data.latest);
        exit(1);
    } else if this_version < update_version {
        prompt_update("outdated", &version_data.latest)
    } else {
        if !silent {
            println!("Your version ({}) is up to date.", VERSION);
        }
    }
    Ok(())
}

fn write_version_data(version_data: &VersionData) -> Result<()> {
    let version_path = get_version_path()?;
    fs::create_dir_all(&version_path.parent().unwrap())?;
    let version_file = File::create(&version_path)?;
    serde_yaml::to_writer(&version_file, &version_data)?;
    Ok(())
}

fn perform_update(dev: bool) -> Result<()> {
    let suffix = if cfg!(target_os = "macos") {
        "-macos"
    } else {
        "-linux"
    };

    let client = get_http_client(dev)?;
    let uri = format!("{}/deepctl{}", GITHUB_RELEASE_LATEST, suffix);
    let mut res = client
        .get(&uri)
        .timeout(std::time::Duration::from_secs(300))
        .send()?
        .error_for_status()?;

    let current_exe = std::env::current_exe()?;
    let tmp_exe = {
        let mut tmp_exe_name = current_exe.as_os_str().to_owned();
        tmp_exe_name.push(".tmp");
        std::path::PathBuf::from(tmp_exe_name)
    };

    {
        let mut tmp_exe_f = File::create(&tmp_exe)?;
        res.copy_to(&mut tmp_exe_f)?;
    }
    fs::set_permissions(&tmp_exe, fs::Permissions::from_mode(0o755))?;
    std::fs::rename(&tmp_exe, &current_exe)?;
    Ok(())
}

fn find_in_chain<T>(e: &anyhow::Error) -> Option<&T>
where
    T: std::error::Error + 'static,
{
    for cause in e.chain() {
        if let Some(te) = cause.downcast_ref::<T>() {
            return Some(te);
        }
    }
    None
}

fn main() {
    let opts = Cli::parse();

    if !matches!(opts.command, Commands::Version { .. }) {
        // User didn't ask for a version check|update, we check anyway.
        main_version_check(opts.dev, false).unwrap_or_else(|e| {
            eprintln!("got an error when performing version check {:?}", e);
            // Non fatal error
        });
    }

    match opts.command {
        Commands::Version { command } => match command {
            VersionSubcommands::Check => main_version_check(opts.dev, true),
            VersionSubcommands::Update => perform_update(opts.dev),
        },
        Commands::Auth { command } => {
            match command {
                AuthCommands::Login => auth_login(opts.dev),
                AuthCommands::Logout => auth_logout(opts.dev),
                AuthCommands::Token => auth_token(opts.dev),
            }
        }
        Commands::Deploy { command } => match command {
            DeployCommands::List { state } => deploy_list(opts.dev, state),
            DeployCommands::Create { model, task } => deploy_create(&model, task.as_ref(), opts.dev),
            DeployCommands::Info { deploy_id } => deploy_info(&deploy_id, opts.dev),
            DeployCommands::Delete { deploy_id } => deploy_delete(&deploy_id, opts.dev),
        },
        Commands::Infer { model, args, outputs } => infer(&model, &args, &outputs, opts.dev),
        Commands::Model { command } => match command {
            ModelCommands::List => models_list(opts.dev),
            ModelCommands::Info { model } => model_info(&model, opts.dev),
        },
    }
    .unwrap_or_else(|e| {
        if let Some(de) = find_in_chain::<DeepCtlError>(&e) {
            if matches!(de, DeepCtlError::NotLoggedIn(..)) {
                eprintln!("Not logged in. Please call `deepctl auth login`");
                exit(1)
            }
        }
        eprintln!("Failed: {:?}", e);
        exit(1)
    })
}

// deepctl auth signup
// deepctl auth login
// deepctl auth logout
// deepctl auth whoami
// deepctl models list
// deepctl deploys create--model=google/mt5-small --provider=huggingface
// deepctl deploys list
// deepctl deploys status --deploy=fdlkjfdslkj
// deepctl deploys delete --deploy=fdlkjfdslkj
