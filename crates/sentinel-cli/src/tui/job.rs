use anyhow::{bail, Context, Result};
use std::{
    io::Read,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};
const OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
const ERROR_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Audit,
    Diff,
    Explain,
    Preview,
    Index,
    Verify,
}
pub struct Completed {
    pub kind: Kind,
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
}
pub struct Job {
    child: Child,
    pub kind: Kind,
    pub started: Instant,
    timeout: Duration,
    stdout: Receiver<std::io::Result<Vec<u8>>>,
    stderr: Receiver<std::io::Result<Vec<u8>>>,
    output: Option<Vec<u8>>,
    errors: Option<Vec<u8>>,
    exited: Option<(i32, Instant)>,
}
fn reader(input: impl Read + Send + 'static, limit: usize) -> Receiver<std::io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = vec![];
        let result = input
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    receiver
}
impl Job {
    pub fn spawn(mut command: Command, kind: Kind, timeout: Duration) -> Result<Self> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .context("could not start background command")?;
        let stdout = reader(child.stdout.take().unwrap(), OUTPUT_LIMIT);
        let stderr = reader(child.stderr.take().unwrap(), ERROR_LIMIT);
        Ok(Self {
            child,
            kind,
            started: Instant::now(),
            timeout,
            stdout,
            stderr,
            output: None,
            errors: None,
            exited: None,
        })
    }
    pub fn poll(&mut self) -> Result<Option<Completed>> {
        if self.started.elapsed() > self.timeout {
            bail!("operation timed out; the owned process will be stopped");
        }
        if self.output.is_none() {
            if let Ok(result) = self.stdout.try_recv() {
                self.output = Some(result?);
            }
        }
        if self.errors.is_none() {
            if let Ok(result) = self.stderr.try_recv() {
                self.errors = Some(result?);
            }
        }
        if self.output.as_ref().is_some_and(|v| v.len() > OUTPUT_LIMIT)
            || self.errors.as_ref().is_some_and(|v| v.len() > ERROR_LIMIT)
        {
            bail!("background output exceeded the TUI limit; use the CLI for a larger report");
        }
        if self.exited.is_none() {
            if let Some(status) = self.child.try_wait()? {
                self.exited = Some((status.code().unwrap_or(2), Instant::now()));
            }
        }
        if let Some((code, when)) = self.exited {
            if self.output.is_some() && self.errors.is_some() {
                let stdout = self.output.take().unwrap();
                let stderr = self.errors.take().unwrap();
                return Ok(Some(Completed {
                    kind: self.kind,
                    code,
                    stdout,
                    stderr: String::from_utf8_lossy(&stderr).into(),
                }));
            }
            // Keep buffers while waiting for the other pipe.
            if self.output.is_none() {
                if let Ok(result) = self.stdout.try_recv() {
                    self.output = Some(result?);
                }
            }
            if self.errors.is_none() {
                if let Ok(result) = self.stderr.try_recv() {
                    self.errors = Some(result?);
                }
            }
            if when.elapsed() > Duration::from_secs(2) {
                bail!("command exited without closing its output pipes");
            }
        }
        Ok(None)
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        if self.exited.is_none() {
            sentinel_scanner::terminate_process_tree(&mut self.child);
        }
    }
}
