pub mod docker {

    use std::io::Write;
    use anyhow::{Result, Error, Context};
    use std::process::{Command, Stdio};

    pub const DEEPINFRA_REGISTRY: &str = "registry.deepinfra.com";

    pub fn login(user: &str, pass: &str, registry: &str) -> Result<()> {
        let mut docker_login = Command::new("docker")
            .arg("login")
            .arg("--username").arg(user)
            .arg("--password-stdin")
            .arg(registry)
            .stdin(Stdio::piped())
            .spawn()
            .with_context(|| format!("Failed to execute `docker login`"))?;
        {
            let stdin = docker_login.stdin.as_mut()
                .ok_or(Error::msg(format!("failed to communicate with docker cli")))?;
            stdin.write_all(pass.as_bytes())?;
        }
        let res = docker_login.wait()?;
        if res.success() {
            Ok(())
        } else {
            Err(Error::msg(format!("`docker login` failed: {}", res.to_string())))
        }
    }

    pub fn tag(image: &str, tag: &str) -> Result<()> {
        let mut docker_tag = Command::new("docker")
            .arg("tag")
            .arg(image)
            .arg(tag)
            .spawn()
            .with_context(|| format!("Failed to execute `docker tag`"))?;
        let res = docker_tag.wait()?;
        if res.success() {
            Ok(())
        } else {
            Err(Error::msg(format!("`docker tag` failed {}", res.to_string())))
        }
    }

    pub fn push(image: &str) -> Result<()> {
        let mut docker_tag = Command::new("docker")
        .arg("push")
        .arg(image)
        .spawn()
        .with_context(|| format!("Failed to execute `docker push`"))?;
        let res = docker_tag.wait()?;
        if res.success() {
            Ok(())
        } else {
            Err(Error::msg(format!("`docker push` failed {}", res.to_string())))
        }
    }

    fn deconstruct_name(image: &str) -> (Vec<&str>, Option<&str>) {
        // This doesn't properly handle names that start with http:// or https://
        if let Some((name, tag)) = image.split_once(':') {
            (name.split("/").collect(), Some(tag))
        } else {
            (image.split("/").collect(), None)
        }
    }

    fn sanitize_name(raw: &str) -> String {
        // This only sanitizes uppercase letters
        // There could be other issues
        raw.to_lowercase()
    }

    // return a suggested fully qualified image name (registry/username/reponame) and a prompt (yn) if something looks fishy or requires approval
    pub fn suggest_remote_name(local_name: &str, remote_name: Option<&str>, registry: &str, user: &str) -> (Option<String>, Option<String>) {
        let user = sanitize_name(user);
        let compose_prompt = |given_registry: &str, given_user: &str, not_sure: bool| -> Option<String> {
            let mut res : Vec<String>  = vec![];
            if ! given_registry.eq(registry) {
                res.push(format!("registry looks incorrect (expected {}, got {})", registry, given_registry));
            }
            if ! given_user.eq(&user) {
                res.push(format!("namespace looks incorrect (expected {}, got {})", user, given_user));
            }
            if not_sure || ! res.is_empty() {
                res.push("are you sure".to_owned());
                Some(res.join(", "))
            } else {
                None
            }
        };
        match remote_name {
            Some(remote_name) => {
                let (comps, _tag) = deconstruct_name(remote_name);
                match comps.len() {
                    3 => {
                        let &given_registry = comps.get(0).unwrap();
                        let &given_name = comps.get(1).unwrap();
                        (Some(remote_name.to_owned()), compose_prompt(given_registry, given_name, false))
                    },
                    2 => {
                        let &given_name = comps.get(0).unwrap();
                        (Some(format!("{}/{}", registry, remote_name)), compose_prompt(registry, given_name, false))
                    },
                    1 => (Some(format!("{}/{}/{}", registry, user, remote_name)), compose_prompt(registry, &user, true)),
                    _ => (None, None),
                }
            },
            None => {
                let (comps, _tag) = deconstruct_name(local_name);
                match comps.last() {
                    Some(&base_name) => {
                        let suggested_name = &format!("{}/{}/{}", registry, user, base_name);
                        (Some(suggested_name.to_owned()), compose_prompt(registry, &user, suggested_name.ends_with(local_name)))
                    },
                    // the source name is empty... this is kinda excessive
                    None => (None, None),
                }
            }
        }
    }

}