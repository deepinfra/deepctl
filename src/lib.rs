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

}