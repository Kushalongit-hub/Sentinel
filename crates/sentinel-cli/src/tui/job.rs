use anyhow::{bail, Context, Result};
use std::{
    io::Read,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, TryRecvError},
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
    AuditStatus,
    AuditHistory,
    AuditRevision,
    JobList,
    JobStatus,
    JobResume,
    JobCancel,
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
        for (receiver, buffer) in [
            (&self.stdout, &mut self.output),
            (&self.stderr, &mut self.errors),
        ] {
            if buffer.is_none() {
                match receiver.try_recv() {
                    Ok(result) => *buffer = Some(result.context("background output read failed")?),
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        bail!("background output reader disconnected before returning a result");
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    fn owned_worker() -> Job {
        #[cfg(windows)]
        let mut command = Command::new("cmd.exe");
        #[cfg(windows)]
        command.args(["/c", "echo sentinel& echo diagnostic 1>&2& exit /b 7"]);
        #[cfg(unix)]
        let mut command = Command::new("sh");
        #[cfg(unix)]
        command.args([
            "-c",
            "printf 'sentinel\n'; printf 'diagnostic\n' >&2; exit 7",
        ]);
        Job::spawn(command, Kind::JobStatus, Duration::from_secs(5)).unwrap()
    }

    #[test]
    fn pipe_readers_retain_only_the_limit_and_one_overflow_byte() {
        for (length, expected) in [(0, 0), (8, 8), (9, 9), (100, 9)] {
            let received = reader(Cursor::new(vec![b'x'; length]), 8)
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap();
            assert_eq!(received.len(), expected);
        }
        struct BrokenReader;
        impl Read for BrokenReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("test read failure"))
            }
        }
        assert!(reader(BrokenReader, 8)
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .is_err());
    }

    #[test]
    fn polling_preserves_both_pipes_and_nonzero_exit_status() {
        let mut job = owned_worker();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(completed) = job.poll().unwrap() {
                assert_eq!(completed.code, 7);
                assert_eq!(
                    String::from_utf8(completed.stdout).unwrap().trim(),
                    "sentinel"
                );
                assert_eq!(completed.stderr.trim(), "diagnostic");
                break;
            }
            assert!(Instant::now() < deadline, "owned worker did not finish");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn polling_rejects_disconnected_or_failed_readers_without_waiting_for_deadline() {
        for stderr in [false, true] {
            let mut job = owned_worker();
            let (sender, receiver) = mpsc::channel();
            drop(sender);
            if stderr {
                job.stderr = receiver;
            } else {
                job.stdout = receiver;
            }
            assert!(job
                .poll()
                .err()
                .expect("expected worker failure")
                .to_string()
                .contains("reader disconnected"));
        }
        let mut job = owned_worker();
        let (sender, receiver) = mpsc::channel();
        sender.send(Err(io::Error::other("read failed"))).unwrap();
        job.stdout = receiver;
        assert!(job
            .poll()
            .err()
            .expect("expected worker failure")
            .to_string()
            .contains("output read failed"));
    }

    #[test]
    fn polling_enforces_each_output_limit_and_elapsed_deadline() {
        for stderr in [false, true] {
            let mut job = owned_worker();
            if stderr {
                job.errors = Some(vec![0; ERROR_LIMIT + 1]);
            } else {
                job.output = Some(vec![0; OUTPUT_LIMIT + 1]);
            }
            assert!(job
                .poll()
                .err()
                .expect("expected worker failure")
                .to_string()
                .contains("exceeded the TUI limit"));
        }
        let mut job = owned_worker();
        job.started = Instant::now() - Duration::from_secs(6);
        assert!(job
            .poll()
            .err()
            .expect("expected worker failure")
            .to_string()
            .contains("timed out"));
    }
}
