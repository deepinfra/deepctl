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
        // There are other issues
        raw.to_lowercase()
    }

    pub fn suggest_remote_name(local_name: &str, remote_name: Option<&str>, registry: &str, user: &str) -> Option<String> {
        // Username can contain uppercase letters, which is NOT ok for docker
        let user = sanitize_name(user);
        match remote_name {
            Some(remote_name) => {
                let (comps, _tag) = deconstruct_name(remote_name);
                if let Some(&first) = comps.first() {
                    if first == registry {
                        Some(remote_name.to_owned())
                    } else if first == user {
                        Some(format!("{}/{}", registry, remote_name))
                    } else {
                        Some(format!("{}/{}/{}", registry, user, remote_name))
                    }
                } else {
                    None
                }
            },
            None => {
                let (comps, _tag) = deconstruct_name(local_name);
                if let Some(&last) = comps.last() {
                    Some(format!("{}/{}/{}", registry, user, last))
                } else {
                    None
                }
            }
        }
    }

}