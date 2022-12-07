use linked_hash_map::LinkedHashMap;
use std::process::exit;
use clap::{Parser, Subcommand};
use webbrowser;
use reqwest;
use std::fs;
use dirs;
use std::fs::File;
use std::io::prelude::*;
use yaml_rust::{YamlLoader, YamlEmitter};
use yaml_rust::Yaml;
use std::env;
use reqwest::blocking::multipart;
use version_compare::Version;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use chrono::serde::ts_seconds;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const DEEPINFRA_HOST_PROD: &str = "https://api.deepinfra.com";
const DEEPINFRA_HOST_DEV: &str = "https://localhost:7001";
const LOGIN_PATH: &str = "/github/login";
const VERSION_CHECK_SEC: i64 = 10;



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
    /// deploy a model
    Deploy {
        /// deploys a model
        #[arg(short, long)]
        model: String,
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

    /// test command with subcommands
    Test {
        #[command(subcommand)]
        command: Option<TestSubcommands>,
    },
    /// version command
    Version {
        #[command(subcommand)]
        command: Option<VersionSubcommands>,
    }
}

#[derive(Subcommand)]
enum AuthCommands {
    /// login to Deep Infra
    Login,
    /// logout of Deep Infra
    Logout,
    /// signup for Deep Infra
    Signup,
    /// show the current user
    Whoami,
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
    Version
}

#[derive(Subcommand)]
enum VersionSubcommands {
    /// check for newer version
    Check,
    /// self update to latest version
    Update,
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

fn auth_login(dev: bool) -> std::io::Result<()> {
    println!("auth login");
    let login_id = random_string(32);
    let host = get_host(dev);
    let login_url = format!("{}{}?login_id={}", host, LOGIN_PATH, login_id);
    println!("opening login url: {}", login_url);
    if webbrowser::open(&login_url).is_ok() {
        println!("opened login page");
        println!("waiting for login to complete");

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(dev)
            // Decide on the timeout
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap();

        let backend_login_url = format!(
            "{}{}?login_id={}", host, "/github/cli/login", login_id);
        let res = client.get(backend_login_url).send().unwrap();
        let status = res.status();
        let body = res.text().unwrap();
        if status != reqwest::StatusCode::OK {
            println!("login request failed: {}: body:{}", status, body);
            exit(1);
        }
        // println!("Headers:\n{:#?}", res.headers());
        // println!("Body:\n{}", body);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        // TODO: check if access token is there
        let token = json["access_token"].as_str().unwrap();
        println!("access_token = {}", token);

        let mut m = LinkedHashMap::new();
        m.insert(Yaml::String("access_token".to_string()),
                 Yaml::String(token.to_string()));
        let yaml = Yaml::Hash(m);
        let mut out_str = String::new();
        let mut emitter = YamlEmitter::new(&mut out_str);
        emitter.dump(&yaml).unwrap();
        // file.write_all(out_str.as_bytes())?;
        write_config(&out_str).unwrap();
        println!("access_token {}", get_access_token().unwrap());
        println!("login successful");
        Ok(())
    } else {
        println!("failed to open login page");
        exit(1)
    }
}

fn read_config() -> std::io::Result<String> {
    let config_path = get_config_path()?;
    let mut file = File::open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn get_access_token() -> std::io::Result<String> {
    let config = read_config()?;
    let docs = YamlLoader::load_from_str(&config).unwrap();
    let doc = &docs[0];
    let access_token = doc["access_token"].as_str().unwrap();
    Ok(access_token.to_string())
}

fn write_config(config: &str) -> std::io::Result<()> {
    let config_path = get_config_path()?;
    fs::create_dir_all(&config_path.parent().unwrap())?;
    let mut file = File::create(config_path)?;
    file.write_all(config.as_bytes())?;
    Ok(())
}

fn get_config_path() -> std::io::Result<std::path::PathBuf> {
    let home = dirs::home_dir().unwrap();
    let path = home.join(".deepinfra/");
    let config_path = path.join("config.yaml");
    Ok(config_path)
}

fn get_version_path() -> std::io::Result<std::path::PathBuf> {
    let home = dirs::home_dir().unwrap();
    let path = home.join(".deepinfra/");
    let config_path = path.join("version.yaml");
    Ok(config_path)
}

fn read_version_data() -> std::io::Result<VersionCheck> {
    let config_path = get_version_path()?;
    let mut file = File::open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let version_data = serde_yaml::from_str(&contents).unwrap();

    Ok(version_data)
}

fn auth_logout(_dev: bool) -> std::io::Result<()> {
    // TODO: send request to the backend to let the backend know that the token is no longer valid
    let config_path = get_config_path()?;
    fs::remove_file(config_path)?;
    println!("logout done");
    Ok(())
}

fn models_list(dev: bool) -> std::io::Result<()> {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(dev)
        .build()
        .unwrap();
    let access_token = match get_access_token() {
        Ok(token) => token,
        Err(_) => {
            println!("Not logged in. Please call `deepctl auth login`");
            exit(1)
        }
    };
    let host = get_host(dev);
    let url = format!("{}{}", host, "/models/list");
    let res = client.get(url)
        .bearer_auth(access_token)
        .send().unwrap();
    // println!("Status: {}", res.status());
    // println!("Headers:\n{:#?}", res.headers());
    let body = res.text().unwrap();
    //println!("Body:\n{}", body);
    println!("Models:");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let mut models = json.as_array().unwrap().iter().map(|model| {
        let model_name = model["model_name"].as_str().unwrap();
        let m_type = model["type"].as_str().unwrap();
        (m_type, model_name)
    }).collect::<Vec<(&str, &str)>>();

    models.sort();

    models.iter().for_each(|(m_type, model_name)| {
        println!("{}: {}", m_type, model_name);
    });
    Ok(())
}

fn get_host(dev: bool) -> String {
    let host = match env::var("DEEPINFRA_HOST") {
        Ok(val) => val,
        Err(_) => match dev {
            true => DEEPINFRA_HOST_DEV.to_string(),
            false => DEEPINFRA_HOST_PROD.to_string(),
        }
    };
    host
}

fn infer(model_name: &str, args: Vec<(String, String)>, dev: bool) -> std::io::Result<()> {
    println!("infer model_name: {} {:?}", model_name, args);
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(dev)
        .build()
        .unwrap();
    let access_token = match get_access_token() {
        Ok(token) => token,
        Err(_) => {
            println!("Not logged in. Please call `deepctl auth login`");
            exit(1)
        }
    };
    let host = get_host(dev);
    let url = format!("{}{}{}", host, "/v1/inference/", model_name);

    let mut form = multipart::Form::new();
    for (key, value) in args {
        if value.starts_with("@") {
            form = form.file(key, &value[1..])?;
        } else {
            form = form.text(key, value);
        }
    }

    // println!("form: {:?}", form);
    let res = client.post(url)
        .bearer_auth(access_token)
        .multipart(form)
        .send().unwrap();
    // println!("Status: {}", res.status());
    // println!("Headers:\n{:#?}", res.headers());
    let body = res.text().unwrap();
    println!("{}", body);
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

fn check_version_with_server(dev: bool) -> std::io::Result<VersionCheck> {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(dev)
        .build()
        .unwrap();
    let host = get_host(dev);

    let now: DateTime<Utc> = Utc::now();



    let url = format!("{}{}?version={}", host, "/cli/version", VERSION);
    let res = client.get(url).send().unwrap();
    let body = res.text().unwrap();
    // println!("{}", body);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
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

fn version_check(dev: bool) -> std::io::Result<()> {
    let version_data = check_version_with_server(dev)?;
    do_version_check(&version_data)?;
    Ok(())
}

fn main_version_check(dev: bool) -> std::io::Result<()> {
    let mut version_data: VersionCheck = read_version_data()?;
    // println!("min_version: {}", version_data.min);
    // println!("update_version: {}", version_data.update);
    // println!("latest_version: {}", version_data.latest);
    // println!("last_check: {}", version_data.last_check);
    version_data = if version_data.last_check < Utc::now() - Duration::seconds(VERSION_CHECK_SEC) {
        println!("checking version with server...");
        check_version_with_server(dev)?
    } else {
        version_data
    };
    do_version_check(&version_data)?;
    Ok(())
}

fn do_version_check(version_data: &VersionCheck) -> std::io::Result<()> {
    let this_version = Version::from(VERSION).unwrap();
    let min_version = Version::from(&version_data.min).unwrap();
    let update_version = Version::from(&version_data.update).unwrap();

    if this_version < min_version {
        println!("Your version {} is too old. Please update to the latest version {}.",
                 VERSION, version_data.latest);
        println!("Update to the latest version using `deepctl version update`");
        exit(1);
    } else if this_version < update_version {
        println!("Your version ({}) is outdated. Please update to the latest version {}.",
                 VERSION, version_data.latest);
        println!("Update to the latest version using `deepctl version update`");
    } else {
        println!("Your version is up to date.");
    }
    Ok(())
}

fn write_version_data(version_data: &VersionCheck) -> std::io::Result<()> {
    let version_path = get_version_path()?;
    fs::create_dir_all(&version_path.parent().unwrap())?;
    let mut version_file = File::create(&version_path)?;
    let yaml = serde_yaml::to_string(&version_data).unwrap();
    version_file.write_all(yaml.as_bytes())?;
    Ok(())
}

fn main() {
    let opts = Cli::parse();

    if !matches!(opts.command, Commands::Version{..}) {
        main_version_check(opts.dev).unwrap();
    }

    match opts.command {
        Commands::Auth { command } => {
            match command {
                AuthCommands::Login => auth_login(opts.dev).unwrap(),
                AuthCommands::Logout => auth_logout(opts.dev).unwrap(),
                AuthCommands::Signup => println!("signup"),
                AuthCommands::Whoami => println!("whoami"),
            }
        }
        Commands::Deploy { model } => println!("deploy {}", model),
        Commands::Infer { model, args} => infer(&model, args, opts.dev).unwrap(),
        Commands::Model { command } => {
            match command {
                ModelCommands::List => models_list(opts.dev).unwrap(),
                ModelCommands::Info { model } => println!("info {}", model),
            }
        }
        Commands::Test { command } => {
            match command {
                Some(TestSubcommands::Command1) => println!("test command1"),
                Some(TestSubcommands::Command2) => println!("test command2"),
                Some(TestSubcommands::Version) => println!("test version"),
                None => println!("test"),
            }
        }
        Commands::Version { command } => {
            match command {
                Some(VersionSubcommands::Check) => version_check(opts.dev).unwrap(),
                Some(VersionSubcommands::Update) => println!("update"),
                None => println!("{}", VERSION),
            }
        }
    }
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