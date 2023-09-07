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
use chrono::{self, TimeZone};
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

pub enum Auth {
    None,
    Optional,
    Required,
    Manual(String),
}

#[derive(Error, Debug)]
pub enum DeepCtlError {
    #[error("Error: {0}")]
    Error(String),
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
        model: Option<String>,
        /// model version
        #[arg(long)]
        version: Option<String>,
        /// deploy_id
        #[arg(short, long)]
        deploy_id: Option<String>,
        /// inference arguments (eg. -i k=v -i k2=v2)
        #[arg(short('i'), value_parser = infer_args_parser)]
        args: Vec<(String, String)>,
        /// inference output (eg. -i images=dir/image.{IDX}.{EXT})
        #[arg(short('o'), value_parser = infer_out_parser)]
        outputs: Vec<(String, String)>,
    },
    /// Push a local docker image to deepinfra registry for custom inference
    Push {
        /// an existing local image name to be pushed
        source_image: String,
        /// an optional remote image name (it would be inferred otherwise)
        target_image: Option<String>,
        /// assume yes
        #[arg(short('y'), default_value_t=false)]
        assume_yes: bool,
    },
    /// Query inference logs
    Log {
        /// query logs for this deploy_id
        deploy_id: String,
        /// from timestamp in YYYY-MM-DD, YYYY-MM-DD HH:MM:SS(.sss), or unix timestamp in fractional seconds (inclusive)
        #[arg(long)]
        from: Option<String>,
        /// to   timestamp in YYYY-MM-DD, YYYY-MM-DD HH:MM:SS(.sss), or unix timestamp in fractional seconds (exclusive)
        #[arg(long)]
        to: Option<String>,
        /// limit the number of returned log lines
        #[arg(long, default_value_t=100)]
        limit: i32,
        /// print new log lines as they become available
        #[arg(short, long, default_value_t=false)]
        follow: bool,
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
    /// store the token manually
    SetToken {
        token: String,
    },
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

#[derive(Serialize, Deserialize, ValueEnum, Eq, PartialEq, Clone, Debug)]
#[serde(rename_all="kebab-case")]
enum ModelVisibility {
    Private,
    Public,
    All,
}

#[derive(Subcommand)]
enum ModelCommands {
    /// list models
    List {
        #[arg(long, default_value="all")]
        visibility: ModelVisibility,
    },
    /// get model info
    Info {
        /// model name
        #[arg(short('m'), long)]
        model: String,
        /// model version
        #[arg(short('v'), long)]
        version: Option<String>,
    },
    /// get available model versions
    Versions {
        /// model name
        #[arg(short('m'), long)]
        model: String,
    },
    Set {
        model: String,
        /// short description
        #[arg(long)]
        description: Option<String>,
        /// whether the model is public (visible to all users) or private (visible only to you)
        #[arg(long)]
        public: Option<bool>,
        /// github link for model project
        #[arg(long)]
        github_url: Option<String>,
        /// link to paper associated with model
        #[arg(long)]
        paper_url: Option<String>,
        /// link to license
        #[arg(long)]
        license_url: Option<String>,
        /// a URL or @path/to/file.jpg to a cover image
        #[arg(long)]
        cover_image: Option<String>,
        /// a @path/to/file to a model readme
        #[arg(long)]
        readme: Option<String>,
    }
}

#[derive(Subcommand)]
enum VersionSubcommands {
    /// show current version
    Info,
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
    auth: Auth,
    builder_map: BM,
) -> Result<reqwest::blocking::Response>
where
    BM: FnOnce(reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder,
{
    let client = get_http_client(dev)?;
    let host = get_host(dev);
    let mut rb = client.request(method, format!("{}{}", host, path));

    match auth {
        Auth::Optional => {
            let access_token = get_access_token(dev);
            if access_token.is_ok() {
                rb = rb.bearer_auth(access_token.unwrap());
            }
        }
        Auth::Required => {
            let access_token = get_access_token(dev).map_err(DeepCtlError::NotLoggedIn)?;
            rb = rb.bearer_auth(access_token);
        }
        Auth::Manual(access_token) => {
            rb = rb.bearer_auth(access_token);
        }
        Auth::None => {}
    }
    rb = builder_map(rb);

    Ok(rb.send()?)
}

fn get_response(
    path: &str,
    method: Method,
    dev: bool,
    auth: Auth,
) -> Result<reqwest::blocking::Response> {
    get_response_extra(path, method, dev, auth, |rb| rb)
}

fn get_parsed_response_extra<BM>(
    path: &str,
    method: Method,
    dev: bool,
    auth: Auth,
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
    auth: Auth,
) -> Result<serde_json::Value> {
    get_parsed_response_extra(path, method, dev, auth, |rb| rb)
}

fn build_path<I, K, V>(path: &str, params: I) -> Result<String>
    where
        I: IntoIterator,
        I::Item: core::borrow::Borrow<(K, V)>,
        K: AsRef<str>,
        V: AsRef<str>
{
    const FAKE_HOST: &str = "http://example.com";
    let url = reqwest::Url::parse_with_params(&format!("{}{}", FAKE_HOST, path), params)?;
    let path = reqwest::Url::parse(FAKE_HOST)?.make_relative(&url).unwrap();
    Ok(format!("/{}", path))
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
            Auth::None,
            |rb| rb.timeout(std::time::Duration::from_secs(300)),
        ).context("waiting for auth result from backend")?;
        let token = json.get("access_token")
            .and_then(|v| v.as_str())
            .ok_or(DeepCtlError::ApiMismatch("login should return access_token".into()))?;

        auth_set_token(token, dev, false)?;
    } else {
        println!("failed to open login page");
        println!("please go http://deepinfra.com/dash/api_keys and paste your API KEY:");
        let token = stdin_read_token()?;
        auth_set_token(&token, dev, true)?;
    }
    println!("login successful");
    Ok(())
}

fn stdin_read_token() -> Result<String> {
    let mut buffer = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut buffer)?;
    Ok(buffer.trim().to_owned())
}

fn verify_token(token: &str, dev: bool) -> bool {
    let res = get_response("/v1/me", Method::GET, dev, Auth::Manual(token.to_owned()));
    res.is_ok() && res.unwrap().status() == reqwest::StatusCode::OK
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

fn auth_docker_login(token: &str, dev: bool, _user_provided: bool) -> Result<()> {
    Ok(deepctl::docker::login(&get_display_name(dev)?, token, deepctl::docker::DEEPINFRA_REGISTRY)?)
}

fn auth_set_token(token: &str, dev: bool, user_provided: bool) -> Result<()> {
    if user_provided && !verify_token(token, dev) {
        return Err(DeepCtlError::BadInput("token is not valid".to_owned()).into());
    }
    write_config(&ConfigData { access_token: token.into() }, dev)?;
    println!("token stored successfully");
    println!("--- running docker login ---");
    let docker_res = auth_docker_login(token, dev, user_provided);
    println!("--- docker login finished ---");
    docker_res.or_else(|e| {
        eprintln!("Failed to store docker credentials. `deepctl push` would likely not work: {:?}", e);
        Ok(())
    })
}

fn get_http_client(dev: bool) -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(dev)
        .build()?)
}

fn _model_list_api(public: bool, dev: bool) -> Result<Vec<(String, String)>> {
    let path = if public { "/models/list" } else { "/models/private/list" };
    let auth = if public { Auth::Optional } else { Auth::Required };
    let json = get_parsed_response(path, Method::GET, dev, auth)?;
    let mut models = json
        .as_array()
        .ok_or(DeepCtlError::ApiMismatch("/models/list doesn't contain a models array".into()))?
        .iter()
        .filter_map(|model| {
            if let (Some(m_type), Some(model_name)) = (
                    model.get("type").and_then(|prop| prop.as_str()),
                    model.get("model_name").and_then(|prop| prop.as_str())) {
                Some((m_type.to_owned(), model_name.to_owned()))
            } else {
                None
            }
        })
        .collect::<Vec<(String, String)>>();

    models.sort();

    Ok(models)
}

fn models_list(visibility: ModelVisibility, dev: bool) -> Result<()> {
    match visibility {
        ModelVisibility::Private => {
            print_models(&mut _model_list_api(false, dev)?);
        },
        ModelVisibility::Public => {
            print_models(&mut _model_list_api(true, dev)?);
        },
        ModelVisibility::All => {
            let mut public = _model_list_api(true, dev)?;
            println!("Public Models:");
            print_models(&mut public);
            let access_token = get_access_token(dev);
            if access_token.is_ok() {
                let mut private = _model_list_api(false, dev)?;
                println!();
                println!("Private Models:");
                print_models(&mut private);
            }
        },
    };

    Ok(())
}

fn print_models(models: &mut Vec<(String, String)>) {
    models.sort();

    models.iter().for_each(|(m_type, model_name)| {
        println!("{}: {}", m_type, model_name);
    });
}

fn model_info(model: &str, version: Option<&str>, dev: bool) -> Result<()> {
    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(version) = version {
        params.push(("version".to_owned(), version.to_owned()));
    }
    let json = get_parsed_response(
        &build_path(&format!("/models/{}", model), params)?,
        Method::GET, dev, Auth::Optional)?;

    fn get_str<'a>(json: &'a serde_json::Value, key: &str) -> Result<&'a str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .ok_or(DeepCtlError::ApiMismatch(format!("model info should contain {} of type string", key)).into())
    }

    fn handle_data_uri(content: &str) -> String {
        if content.starts_with("data:") {
            return "(binary)".to_owned()
        } else {
            return content.to_owned()
        }
    }

    let price_str: String = {
        let pricing = json.get("pricing")
            .ok_or(DeepCtlError::ApiMismatch(format!("model info should contain pricing object")))?;
        let ptype = get_str(pricing, "type")?;
        let (key, coef, sfx) = if ptype.eq("time") {
            ("cents_per_sec", 0.01, "sec")
        } else {
            ("cents_per_output_token", 10.0, "Ktoken")
        };
        let val = pricing.get(key)
            .and_then(|v| v.as_f64())
            .ok_or(DeepCtlError::ApiMismatch(format!("model.pricing should contain {} of type number", key)))?;
        format!("${:.4}/{}", val * coef, sfx)
    };

    // println!("{:?}", json);
    println!("model: {}", model);
    println!("type: {}", get_str(&json, "type")?);
    println!("version: {}", get_str(&json, "version")?);
    println!("public: {}", json.get("public").and_then(|v| v.as_bool()) != Some(false));
    println!("pricing: {}", price_str);
    if let Ok(mask_token) = get_str(&json, "mask_token") {
        println!("mask token: {}", mask_token);
    }
    if let Ok(desc) = get_str(&json, "description") {
        println!("description: {}", desc);
    }
    if let Some(meta) = json.get("meta").and_then(|v| v.as_object()) {
        if let Some(github_url) = meta.get("github_url").and_then(|v| v.as_str()) {
            println!("github: {}", github_url);
        }
        if let Some(paper_url) = meta.get("paper_url").and_then(|v| v.as_str()) {
            println!("paper: {}", paper_url);
        }
        if let Some(license_url) = meta.get("license_url").and_then(|v| v.as_str()) {
            println!("license: {}", license_url);
        }
        if let Some(cover_img_url) = meta.get("cover_img_url").and_then(|v| v.as_str()) {
            println!("cover_image: {}", handle_data_uri(cover_img_url));
        }
        if let Some(readme) = meta.get("readme").and_then(|v| v.as_str()) {
            println!("README:\n{}\n", handle_data_uri(readme));
        }
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

fn model_versions(model_name: &str, dev: bool) -> Result<()> {
    let json = get_parsed_response(
        &format!("/models/{}/versions", model_name),
        Method::GET,
        dev,
        Auth::Optional)?;
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

fn file_to_data_url(path: &str) -> Result<String> {
    let content = read_binary_file(path)?;
    let b64_content = base64::encode(content);
    Ok(format!("data:;base64,{}", b64_content))
}

fn model_set(
    model: &str,
    description: Option<&str>,
    public: Option<bool>,
    github_url: Option<&str>,
    paper_url: Option<&str>,
    license_url: Option<&str>,
    cover_image: Option<&str>,
    readme: Option<&str>,
    dev: bool,
) -> Result<()> {
    let mut meta_body = std::collections::HashMap::new();
    if let Some(description) = description {
        meta_body.insert("description".to_owned(), description.to_owned());
    }
    if let Some(github_url) = github_url {
        meta_body.insert("github_url".to_owned(), github_url.to_owned());
    }
    if let Some(paper_url) = paper_url {
        meta_body.insert("paper_url".to_owned(), paper_url.to_owned());
    }
    if let Some(license_url) = license_url {
        meta_body.insert("license_url".into(), license_url.to_owned());
    }
    if let Some(cover_image) = cover_image {
        let cover_image_url = if cover_image.starts_with("@") {
            file_to_data_url(&cover_image[1..])?
        } else if cover_image.starts_with("http://") || cover_image.starts_with("https://") {
            cover_image.to_owned()
        } else {
            return Err(DeepCtlError::BadInput(
                "the cover_image should be an http(s) url or @path/to/local/file".to_owned()).into());
        };
        meta_body.insert("cover_img_url".to_owned(), cover_image_url);
    }
    if let Some(readme) = readme {
        let readme_url = if readme.starts_with("@") {
            file_to_data_url(&readme[1..])?
        } else {
            return Err(DeepCtlError::BadInput(
                "the readme should be in @path/to/local/file format".to_owned()).into());
        };
        meta_body.insert("readme".to_owned(), readme_url);
    }
    if !meta_body.is_empty() {
        let body = serde_json::to_string(&meta_body)?;
        let res = get_response_extra(
            &format!("/models/{}/meta", model),
            Method::POST, dev, Auth::Required, |rb|
                rb.header("Content-Type", "application/json").body(body)
        ).context("updating model metadata")?;
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(DeepCtlError::BadInput(format!("the model {} doesn't exist", model)).into());
        } else if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(DeepCtlError::BadInput(format!("lacking permissions to edit model {}", model)).into());
        }
    }

    if let Some(public) = public {
        let body = serde_json::to_string(&serde_json::json!({"public": public}))?;
        let res = get_response_extra(
            &format!("/models/{}/publicity", model),
            Method::POST, dev, Auth::Required, |rb|
               rb.header("Content-Type", "application/json").body(body)
        ).context("setting model publicity")?;
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(DeepCtlError::BadInput(format!("the model {} doesn't exist", model)).into());
        } else if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(DeepCtlError::BadInput(format!("lacking permissions to edit model {}", model)).into());
        }
    }
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
    let json = get_parsed_response("/deploy/list/", Method::GET, dev, Auth::Required)?;
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
    let json = get_parsed_response(&format!("/deploy/{}", deploy_id), Method::GET, dev, Auth::Required)?;
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

fn deploy_delete(deploy_id: &str, dev: bool) -> Result<()> {
    get_response(&format!("/deploy/{}", deploy_id), Method::DELETE, dev, Auth::Required)?
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
    let json = get_parsed_response_extra("/deploy/hf/", Method::POST, dev, Auth::Required, |rb| {
        rb.header("Content-type", "application/json").body(body)
    })?;

    let deploy_id = json.get("deploy_id")
        .and_then(|v| v.as_str())
        .ok_or(DeepCtlError::ApiMismatch("delpoy model response should contain deploy_id".into()))?;
    println!("deployed {} {:?} -> {}", model_name, &task, deploy_id);
    let mut last_status = String::new();
    loop {
        let tjson =
            get_parsed_response(&format!("/deploy/{}", &deploy_id), Method::GET, dev, Auth::Required)?;
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
        let (raw_value, file_name) = if inp_value.starts_with("@") {
            (read_binary_file(&inp_value[1..])?, Some(inp_value[1..].to_owned()))
        } else if inp_value.starts_with("base64:") {
            (parse_base64(&inp_value[7..])?, Some("filename.ext".to_owned()))
        } else {
            (inp_value.as_bytes().to_vec(), None)
        };

        let mut part = multipart::Part::bytes(raw_value);
        // the filename forces the backend to treat this data as binary
        match file_name {
            Some(ref name) => {
                part = part.file_name(name.to_owned());
                let guess = mime_guess::from_path(name);
                match guess.first() {
                    Some(mime) => {
                        part = part.mime_str(mime.as_ref())?;
                    }
                    None => {
                        part = part.mime_str("application/octet-stream")?;
                    }
                }
            }
            None => {
                part = part.mime_str("text/plain")?;
            }
        }

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

fn get_display_name(dev: bool) -> Result<String> {
    let profile = get_parsed_response("/v1/me", Method::GET, dev, Auth::Required)
        .with_context(|| format!("failed to fetch profile"))?;
    Ok(profile.get("display_name")
        .and_then(|dn| dn.as_str())
        .ok_or(DeepCtlError::ApiMismatch("/v1/me doesn't contain display_name".into()))?
        .to_owned())
}

fn prompt(msg: &str, assume_yes: bool) -> Result<String> {
    let actual_msg = if assume_yes {
        format!("{} [Yn] -> ASSUMING YES\n", msg)
    } else {
        format!("{} [Yn] ", msg)
    };
    eprint!("{}", actual_msg);
    if assume_yes {
        return Ok("y".to_owned());
    }
    let mut buffer = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut buffer)?;
    Ok(buffer.trim().to_owned())
}

fn push(source_image: &str, target_image: Option<&str>, assume_yes: bool, dev: bool) -> Result<()> {
    let display_name = get_display_name(dev)?;
    // if the source is already properly tagged, and there is no target provided, just use the source as-is
    // let target_image = if source_image.starts_with(deepctl::docker::DEEPINFRA_REGISTRY) && target_image == None {
    //     Some(source_image)
    // } else {
    //     target_image
    // };
    if let (Some(full_target_image), sure_prompt) = deepctl::docker::suggest_remote_name(
            source_image, target_image,
            deepctl::docker::DEEPINFRA_REGISTRY, &display_name) {
        eprintln!("Pushing {} to {}", source_image, full_target_image);
        if let Some(sure_prompt) = sure_prompt {
            let response = prompt(&sure_prompt, assume_yes)?;
            if !(response == "" || response.to_lowercase() == "y") {
                return Ok(());
            }
        }
        deepctl::docker::tag(source_image, &full_target_image)?;
        deepctl::docker::push(&full_target_image)?;
        Ok(())
    } else {
        Err(DeepCtlError::BadInput("can't figure out where to push, please specify proper TARGET_IMAGE".to_owned()).into())
    }
}

fn infer(model_name: Option<&str>, version: Option<&str>, deploy_id: Option<&str>, args: &Vec<(String, String)>, outs: &Vec<(String, String)>, dev: bool) -> Result<()> {
    let form = infer_body(args)?;

    if ((model_name.is_some() || version.is_some()) as i32) + (deploy_id.is_some() as i32) != 1 {
        return Err(DeepCtlError::BadInput(
            "exactly ONE of --model(+ --version) or --deploy-id is required for inference".to_owned()).into());
    }
    if version.is_some() && model_name.is_none() {
        return Err(DeepCtlError::BadInput(
            "can not pass --version without --model".to_owned()).into());
    }

    let path = if model_name.is_some() {
        let mut params: Vec<(String, String)> = vec![];
        if let Some(version) = version {
            params.push(("version".into(), version.to_owned()));
        }
        build_path(&format!("/v1/inference/{}", model_name.unwrap()), params.iter())?
    } else {
        format!("/v1/inference/deploy/{}", deploy_id.unwrap())
    };

    let response = get_response_extra(
        &path,
        Method::POST,
        dev,
        Auth::Optional,
        move |rb| {
            rb.timeout(std::time::Duration::from_secs(1800))
                .multipart(form)
        },
    )?;

    if !response.status().is_success() {
        let status = response.status();
        let error_json: serde_json::Value = serde_json::from_str(&response.text()?)?;
        let error_str = serde_json::to_string_pretty(&error_json)?;
        return Err(DeepCtlError::Error(format!("{}: {}", status, error_str)).into());
    }

    let json: serde_json::Value = serde_json::from_str(&response.text()?)?;

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
        Auth::None,
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

#[derive(PartialEq, Debug)]
enum FmtType {
    HumanShort,
    HumanLong,
    HumanLongNs,
    Unix,
    UnixNs,
}

impl FmtType {
    fn as_str(&self) -> &'static str {
        match self {
            FmtType::HumanShort => "%F",
            FmtType::HumanLong => "%F %T",
            FmtType::HumanLongNs => "%F %T%.3f",
            FmtType::Unix => "%s",
            FmtType::UnixNs => "%s%.3f",
        }
    }

    fn parse<T: chrono::offset::TimeZone>(&self, base: &T, s: &str) -> Option<chrono::DateTime<T>>  {
        match self {
            FmtType::HumanShort => {
                let date = chrono::NaiveDate::parse_from_str(s, self.as_str()).ok();
                let date_time = date.and_then(|d| d.and_hms_opt(0, 0, 0));
                date_time.and_then(|dt| base.from_local_datetime(&dt).latest())
            },
            _ => base.datetime_from_str(s, self.as_str()).ok(),
        }
    }
}

fn ts_ns_to_human(ns: &str) -> Result<String> {
    let dt = chrono::Local.datetime_from_str(ns, FmtType::UnixNs.as_str())?;
    let df = dt.format(FmtType::HumanLongNs.as_str());
    Ok(format!("{}", df))
}

fn ts_human_to_ns(human: &str) -> Option<String> {
    for fmt_type in &[FmtType::HumanShort, FmtType::HumanLong, FmtType::HumanLongNs, FmtType::Unix, FmtType::UnixNs] {
        match fmt_type.parse(&chrono::Local, human) {
            Some(dt) => return Some(format!("{}", dt.format(FmtType::UnixNs.as_str()))),
            None => (), // eprintln!("failed to parse with {}", fmt_type.as_str()),
        }
    }
    None
}

fn log_query_raw<F: Fn(&str, &str)>(dev: bool, deploy_id: &str, from: Option<String>, to: Option<String>, limit: i32, iter: F) -> Result<()> {
    let mut params: Vec<(String, String)> = vec![];
    params.push(("deploy_id".into(), deploy_id.to_owned()));
    if let Some(from) = from {
        params.push(("from".into(), ts_human_to_ns(&from)
            .ok_or(DeepCtlError::BadInput("bad from timstamp".to_owned()))?));
    }
    if let Some(to) = to {
        params.push(("to".into(), ts_human_to_ns(&to)
            .ok_or(DeepCtlError::BadInput("bad to timstamp".to_owned()))?));
    }
    params.push(("limit".into(), format!("{}", limit)));

    let res = get_parsed_response(&build_path("/v1/logs/query", params.iter())?, Method::GET, dev, Auth::Required)?;

    res.get("entries")
            .ok_or(DeepCtlError::ApiMismatch("expected entries array".into()))?
            .as_array()
            .ok_or(DeepCtlError::ApiMismatch("expected entries array".into()))?
            .iter()
            .for_each(|item| {
        let ts_line = item.as_array().unwrap();
        let ts_raw = ts_line.get(0).unwrap().as_str().unwrap();
        let line = ts_line.get(1).unwrap().as_str().unwrap();

        iter(ts_raw, line);
    });

    Ok(())
}

fn log_query(dev: bool, deploy_id: String, from: Option<String>, to: Option<String>, limit: i32, follow: bool) -> Result<()> {
    if !follow {
        log_query_raw(dev, &deploy_id, from, to, limit, |ts, line| {
            println!("{} {}", ts_ns_to_human(ts).unwrap(), line);
        })
    } else {
        if from.is_some() || to.is_some() {
            return Err(DeepCtlError::BadInput("-f/--follow is incompatible with --from/--to".into()).into());
        }
        log_tail(dev, deploy_id, limit)
    }
}

fn log_tail(dev: bool, deploy_id: String, limit: i32) -> Result<()> {
    let last_ts = std::cell::RefCell::new("0".to_owned());
    let visitor = |ts: &str, line: &str| {
        // avoid repeated lines (we always get the last line because from == last_ts)
        if ts > last_ts.borrow().as_str() {
            println!("{} {}", ts_ns_to_human(ts).unwrap(), line);
            last_ts.replace(ts.to_owned());
        }
    };
    log_query_raw(dev, &deploy_id, None, None, limit, &visitor)?;

    loop {
        std::thread::sleep(std::time::Duration::from_millis(2000));
        let last_ts_copy = last_ts.borrow().clone();
        // in case of very intensive logs 100 might not be enough for every 2s (i.e we'd start lagging behind), so honor the passed limit if larger
        log_query_raw(dev, &deploy_id, Some(last_ts_copy), None, std::cmp::max(limit, 100), &visitor)?;
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

fn print_version() -> Result<()> {
    println!("deepctl {}", VERSION);
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
            VersionSubcommands::Info => print_version(),
        },
        Commands::Auth { command } => {
            match command {
                AuthCommands::Login => auth_login(opts.dev),
                AuthCommands::Logout => auth_logout(opts.dev),
                AuthCommands::Token => auth_token(opts.dev),
                AuthCommands::SetToken { token } => auth_set_token(&token, opts.dev, true),
            }
        }
        Commands::Deploy { command } => match command {
            DeployCommands::List { state } => deploy_list(opts.dev, state),
            DeployCommands::Create { model, task } => deploy_create(&model, task.as_ref(), opts.dev),
            DeployCommands::Info { deploy_id } => deploy_info(&deploy_id, opts.dev),
            DeployCommands::Delete { deploy_id } => deploy_delete(&deploy_id, opts.dev),
        },
        Commands::Push { source_image, target_image, assume_yes } => push(&source_image, target_image.as_deref(), assume_yes, opts.dev),
        Commands::Infer {
            model,
            version,
            deploy_id,
            args,
            outputs
        } => infer(model.as_deref(), version.as_deref(), deploy_id.as_deref(), &args, &outputs, opts.dev),
        Commands::Model { command } => match command {
            ModelCommands::List { visibility } => models_list(visibility, opts.dev),
            ModelCommands::Info { model, version } => model_info(&model, version.as_deref(), opts.dev),
            ModelCommands::Versions { model } => model_versions(&model, opts.dev),
            ModelCommands::Set { model, description, public, github_url, paper_url, license_url, cover_image, readme } => model_set(&model, description.as_deref(), public, github_url.as_deref(), paper_url.as_deref(), license_url.as_deref(), cover_image.as_deref(), readme.as_deref(), opts.dev),
        },
        Commands::Log { deploy_id, from, to, limit, follow } => log_query(opts.dev, deploy_id, from, to, limit, follow),
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
