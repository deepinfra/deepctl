use anyhow::{Result, Context};
use chrono::serde::ts_seconds;
use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use dirs;
use linked_hash_map::LinkedHashMap;
use reqwest::blocking::multipart;
use reqwest::{self, Method};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::process::exit;
use thiserror::Error;
use version_compare::Version;
use webbrowser;
use yaml_rust::Yaml;
use yaml_rust::{YamlEmitter, YamlLoader};
use base64;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const DEEPINFRA_HOST_PROD: &str = "https://api.deepinfra.com";
const DEEPINFRA_HOST_DEV: &str = "https://localhost:7001";
const LOGIN_PATH: &str = "/github/login";
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
    #[error("backend returned wrong/unexpected object")]
    ApiMismatch(&'static str),
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct VersionCheck {
    min: String,
    update: String,
    latest: String,
    #[serde(with = "ts_seconds")]
    last_check: DateTime<Utc>,
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
    // /// signup for Deep Infra
    // Signup,
    // /// show the current user
    // Whoami,
}

#[derive(Subcommand)]
enum DeployCommands {
    /// list deployed models
    List {
        /// show only deploys in given state
        #[arg(long, value_enum, default_value_t=DeployState::ACTIVE)]
        state: DeployState,
    },
    /// deploy a new model
    Add {
        #[arg(short, long)]
        model: String,
        #[arg(short, long)]
        task: String,
    },
    /// get information on a particular deployment
    Info { deploy_id: String },
    /// remove a deploymnet
    Delete { deploy_id: String },
}

#[derive(Subcommand)]
enum ModelCommands {
    /// list models
    List,
    /// get model info
    Info {
        /// model name
        #[arg(short, long)]
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
    let client = get_http_client(dev);
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

fn auth_login(dev: bool) -> Result<()> {
    println!("auth login");
    let login_id = random_string(32);
    let host = get_host(dev);
    let login_url = format!("{}{}?login_id={}", host, LOGIN_PATH, login_id);
    println!("opening login url: {}", login_url);
    if webbrowser::open(&login_url).is_ok() {
        println!("opened login page");
        println!("waiting for login to complete");
        let json = get_parsed_response_extra(
            &format!("/github/cli/login?login_id={}", login_id),
            Method::GET,
            dev,
            false,
            |rb| rb.timeout(std::time::Duration::from_secs(300)),
        ).context("waiting for auth result from backend")?;
        let token = json["access_token"].as_str().unwrap();

        let mut m = LinkedHashMap::new();
        m.insert(
            Yaml::String("access_token".to_string()),
            Yaml::String(token.to_string()),
        );
        let yaml = Yaml::Hash(m);
        let mut out_str = String::new();
        let mut emitter = YamlEmitter::new(&mut out_str);
        emitter.dump(&yaml).unwrap();
        // file.write_all(out_str.as_bytes())?;
        write_config(&out_str, dev).context("storing login token")?;
        // println!("access_token {}", get_access_token().unwrap());
        println!("login successful");
        Ok(())
    } else {
        println!("failed to open login page");
        exit(1)
    }
}

fn read_config(dev: bool) -> Result<String> {
    let config_path = get_config_path(dev)?;
    let mut file = File::open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn get_access_token(dev: bool) -> Result<String> {
    let config = read_config(dev)?;
    let docs = YamlLoader::load_from_str(&config)?;
    let doc = &docs[0];
    let access_token = doc["access_token"]
        .as_str()
        .ok_or(DeepCtlError::BadConfig)?;
    Ok(access_token.to_string())
}

fn write_config(config: &str, dev: bool) -> Result<()> {
    let config_path = get_config_path(dev)?;
    fs::create_dir_all(&config_path.parent().unwrap())?;
    let mut file = File::create(config_path)?;
    file.write_all(config.as_bytes())?;
    Ok(())
}

fn get_di_dir() -> Result<std::path::PathBuf> {
    Ok(dirs::home_dir()
        .ok_or(DeepCtlError::BadEnv("home_dir"))?
        .join(".deepinfra"))
}

fn get_config_path(dev: bool) -> Result<std::path::PathBuf> {
    Ok(get_di_dir()?
        .join(".deepinfra/")
        .join(if dev {
            "config_dev.yaml"
        } else {
            "config.yaml"
        }))
}

fn get_version_path() -> Result<std::path::PathBuf> {
    Ok(get_di_dir()?.join("version.yaml"))
}

fn read_version_data() -> Result<VersionCheck> {
    let config_path = get_version_path()?;
    let mut file = File::open(&config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    Ok(serde_yaml::from_str(&contents)?)
}

fn auth_logout(_dev: bool) -> Result<()> {
    // TODO: send request to the backend to let the backend know that the token is no longer valid
    let config_path = get_config_path(_dev)?;
    fs::remove_file(config_path)?;
    println!("logout done");
    Ok(())
}

fn get_http_client(dev: bool) -> reqwest::blocking::Client {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(dev)
        .build()
        .unwrap();
    client
}

fn models_list(dev: bool) -> Result<()> {
    let json = get_parsed_response("/models/list", Method::GET, dev, true)?;
    let mut models = json
        .as_array()
        .unwrap()
        .iter()
        .map(|model| {
            let model_name = model["model_name"].as_str().unwrap();
            let m_type = model["type"].as_str().unwrap();
            (m_type, model_name)
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

    // println!("{:?}", json);
    println!("model: {}", model);
    println!("type: {}", json["type"].as_str().unwrap());
    if let Some(mask_token) = json["mask_token"].as_str() {
        println!("mask token: {}", mask_token);
    }
    println!(
        "CURL invocation:\n\n {}\n",
        json["curl_inv"].as_str().unwrap()
    );
    println!(
        "deepctl invocation:\n\n {}\n",
        json["cmdline_inv"].as_str().unwrap()
    );
    println!(
        "Field description:\n\n{}\n",
        json["txt_docs"].as_str().unwrap()
    );
    println!(
        "output example:\n\n{}\n",
        json["out_example"].as_str().unwrap()
    );
    println!(
        "output fields description:\n\n{}\n",
        json["out_docs"].as_str().unwrap()
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
        // .unwrap();
        .ok_or(DeepCtlError::ApiMismatch("/delpoy/list/ result is not an array"))?
        .iter()
        .filter(|d| allowed_statuses.contains(&d["status"].as_str().unwrap()))
        .collect();
    println!("{}", serde_json::to_string_pretty(&deploys).unwrap());
    Ok(())
}

fn deploy_info(deploy_id: &str, dev: bool) -> Result<()> {
    let json = get_parsed_response(&format!("/deploy/{}", deploy_id), Method::GET, dev, true)?;
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
    Ok(())
}

fn deploy_delete(deploy_id: &str, dev: bool) -> Result<()> {
    get_response(&format!("/deply/{}", deploy_id), Method::DELETE, dev, true)?
        .error_for_status()?;
    Ok(())
}

fn deploy_add(model_name: &str, task: &str, dev: bool) -> Result<()> {
    let params = HashMap::from([("model_name", model_name), ("task", task)]);
    let body = serde_json::to_string(&params)?;

    let json = get_parsed_response_extra("/deploy/hf/", Method::POST, dev, true, |rb| {
        rb.header("Content-type", "application/json").body(body)
    })?;

    let deploy_id = json["deploy_id"].as_str().unwrap();
    println!("deployed {} {} -> {}", model_name, task, deploy_id);
    let mut last_status = String::new();
    loop {
        let tjson =
            get_parsed_response(&format!("/deploy/{}", &deploy_id), Method::GET, dev, true)?;
        let status = tjson["status"].as_str().unwrap();
        if status != last_status {
            // print the status replacing the last line
            println!("status: {}", status);
            last_status = String::from(status);
        }
        if status == "initializing" || status == "deploying" {
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }
        // TODO: Non-zero exit status on failed (what about deleted, stopping)?
        println!("\ndeployment {} --> {}", deploy_id, status);
        break;
    }
    Ok(())
}

#[derive(Debug, PartialEq)]
enum InferInputType {
    INTEGER,
    NUMBER,
    TEXT,
    BINARY
}

impl InferInputType {
    fn from_str(inp: &str) -> Option<InferInputType> {
        match inp {
            "integer" => Some(Self::INTEGER),
            "number" => Some(Self::NUMBER),
            "string" => Some(Self::TEXT),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
enum InferInputLocation {
    PARAMS,
    MULTIPART,
}

fn read_binary_file(name: &str) -> Result<Vec<u8>> {
    let mut file = File::open(name)?;
    let mut buf: Vec<u8> = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

fn prase_base64(b64: &str) -> Result<Vec<u8>> {
    Ok(base64::decode(b64)?)
    // let mut reader = std::io::Cursor::new(b64);
    // let mut decoder = base64::read::DecoderReader::from(
    //     &mut reader,
    //     &base64::engine::DEFAULT_ENGINE);

    // // handle errors as you normally would
    // let mut buf = Vec::new();
    // decoder.read_to_end(&mut buf)?;
    // Ok(buf)
}

fn encode_base64(b64_bytes: &Vec<u8>) -> String {
    base64::encode(b64_bytes)
}

type InputMapping = HashMap<String, (InferInputType, InferInputLocation)>;
fn infer_body(mapping: InputMapping, args: Vec<(String, String)>) -> Result<multipart::Form> {
    eprintln!("mapping: {:?}", mapping);
    let mut form = multipart::Form::new();
    let mut params = serde_json::Map::new();
    for (key, inp_value) in args {
        let raw_value = if inp_value.starts_with("@") {
            read_binary_file(&inp_value[1..])?
        } else if inp_value.starts_with("base64:") {
            prase_base64(&inp_value[7..])?
        } else {
            inp_value.as_bytes().to_vec()
        };
        
        if let Some((typ, location)) = mapping.get(&key) {
            match location {
                InferInputLocation::PARAMS => {
                    let parsed_value: serde_json::Value = match typ {
                        InferInputType::INTEGER | InferInputType::NUMBER => serde_json::from_str(String::from_utf8(raw_value)?.trim())?,
                        InferInputType::TEXT => serde_json::Value::String(String::from_utf8(raw_value)?),
                        InferInputType::BINARY => serde_json::Value::String(encode_base64(&raw_value)),
                    };
                    params.insert(key, parsed_value);
                },
                InferInputLocation::MULTIPART => {
                    let mut part = multipart::Part::bytes(raw_value);
                    // If there is no filename, fastapi returns 422
                    part = part.file_name("filename.ext");
                    form = form.part(key, part);
                }
            }
        };
    }
    if !params.is_empty() {
        form = form.text("input", serde_json::to_string(&params)?);
    }
    Ok(form)
}

fn get_model_in_schema(dev: bool, model_name: &str) -> Result<serde_json::Value> {
    let schema_cache = get_di_dir()?
        .join("schemas")
        .join(format!("{}.in.schema.json", model_name.replace("/", ":")));
    if ! schema_cache.exists() {
        let model_info = get_parsed_response(&format!("/models/{}", model_name), Method::GET, dev, false)?;
        let in_schema = model_info.get("in_schema")
            .ok_or(DeepCtlError::ApiMismatch("/models/NAME should contain in_schema"))?;
        fs::create_dir_all(&schema_cache.parent().unwrap())?;
        serde_json::to_writer(File::create(&schema_cache)?, in_schema)?;
    }

    let schema: serde_json::Value = serde_json::from_reader(File::open(&schema_cache)?)?;

    Ok(schema.to_owned())
}

fn schema_to_mapping(schema: serde_json::Value) -> Result<InputMapping> {
    let properties = schema.get("properties")
        .ok_or(DeepCtlError::ApiMismatch("in_schema should have properties"))?
        .as_object()
        .ok_or(DeepCtlError::ApiMismatch("in_schema properties should be hash"))?; 
    let mut res = InputMapping::new();
    for (name, props) in properties {
        let format = props.get("format").and_then(serde_json::Value::as_str);
        if format == Some("binary") {
            res.insert(name.to_owned(), (InferInputType::BINARY, InferInputLocation::MULTIPART));
        } else {
            let raw_inp_type = props.get("type")
                .ok_or(DeepCtlError::ApiMismatch("schema property should have type"))?
                .as_str()
                .ok_or(DeepCtlError::ApiMismatch("schema property type should be string"))?;
            let inp_type = InferInputType::from_str(raw_inp_type)
                .ok_or(DeepCtlError::ApiMismatch("unhandled schema type"))
                .context(format!("type {}", raw_inp_type))?;
            res.insert(name.to_owned(), (inp_type, InferInputLocation::PARAMS));
        }
    }
    Ok(res)
}

fn infer(model_name: &str, args: Vec<(String, String)>, dev: bool) -> Result<()> {
    let schema: serde_json::Value = get_model_in_schema(dev, model_name)?;
    let form = infer_body(schema_to_mapping(schema)?, args)?;

    let json = get_parsed_response_extra(
        &format!("/v1/inference/{}", model_name),
        Method::POST,
        dev,
        false,
        move |rb| {
            rb.timeout(std::time::Duration::from_secs(600))
                .multipart(form)
        },
    )?;

    println!("{}", serde_json::to_string_pretty(&json).unwrap());
    Ok(())
}

fn infer_args_parser(s: &str) -> Result<(String, String), String> {
    // check if s contains exactly one '='
    let mut split = s.split('=');
    if split.clone().count() != 2 {
        return Err("Invalid argument format. Expected `key=value`".to_string());
    }
    let key = split.next().unwrap();
    let value = split.next().unwrap();
    Ok((key.to_string(), value.to_string()))
}

fn check_version_with_server(dev: bool) -> Result<VersionCheck> {
    let now = Utc::now();
    let json = get_parsed_response(
        &format!("/cli/version?version={}", VERSION),
        Method::GET,
        dev,
        false,
    )?;
    let min_version_str = json["min"].as_str().unwrap();

    let update_version_str = json["update"].as_str().unwrap();
    let latest_version_str = json["latest"].as_str().unwrap();
    let version_data = VersionCheck {
        min: min_version_str.to_string(),
        update: update_version_str.to_string(),
        latest: latest_version_str.to_string(),
        last_check: now,
    };

    write_version_data(&version_data)?;

    Ok(version_data)
}

fn main_version_check(dev: bool, force: bool) -> Result<()> {
    let crnt_version_data: Option<VersionCheck> = read_version_data().ok();
    let version_data = if crnt_version_data.is_none()
        || force
        || crnt_version_data.as_ref().unwrap().last_check
            < Utc::now() - Duration::seconds(VERSION_CHECK_SEC)
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
    if let Ok(exe) = std::env::current_exe() {
        if exe
            .as_path()
            .starts_with(dirs::home_dir().unwrap().as_path())
        {
            sudo_str = "";
        }
    }
    println!(
        "Update to the latest version using `{}deepctl version update`",
        sudo_str
    );
}

fn do_version_check(version_data: &VersionCheck, silent: bool) -> Result<()> {
    let this_version = Version::from(VERSION).unwrap();
    let min_version = Version::from(&version_data.min).unwrap();
    let update_version = Version::from(&version_data.update).unwrap();

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

fn write_version_data(version_data: &VersionCheck) -> Result<()> {
    let version_path = get_version_path()?;
    fs::create_dir_all(&version_path.parent().unwrap())?;
    let mut version_file = File::create(&version_path)?;
    let yaml = serde_yaml::to_string(&version_data).unwrap();
    version_file.write_all(yaml.as_bytes())?;
    Ok(())
}

fn perform_update(dev: bool) -> Result<()> {
    let suffix = if cfg!(target_os = "macos") {
        "-macos"
    } else {
        "-linux"
    };

    let client = get_http_client(dev);
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
        main_version_check(opts.dev, false).unwrap();
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
                // AuthCommands::Signup => println!("signup"),
                // AuthCommands::Whoami => println!("whoami"),
            }
        }
        Commands::Deploy { command } => match command {
            DeployCommands::List { state } => deploy_list(opts.dev, state),
            DeployCommands::Add { model, task } => deploy_add(&model, &task, opts.dev),
            DeployCommands::Info { deploy_id } => deploy_info(&deploy_id, opts.dev),
            DeployCommands::Delete { deploy_id } => deploy_delete(&deploy_id, opts.dev),
        },
        Commands::Infer { model, args } => infer(&model, args, opts.dev),
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
