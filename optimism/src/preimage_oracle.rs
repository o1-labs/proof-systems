use crate::cannon::{
    HostProgram, HINT_CLIENT_READ_FD, HINT_CLIENT_WRITE_FD, PREIMAGE_CLIENT_READ_FD,
    PREIMAGE_CLIENT_WRITE_FD,
};
use command_fds::{CommandFdExt, FdMapping};
use os_pipe::{PipeReader, PipeWriter};
use std::os::fd::AsRawFd;
use std::process::{Child, Command};
pub struct PreImageOracle {
    pub cmd: Command,
    pub oracle_client: RW,
    pub hint_writer: RW,
}

pub struct ReadWrite<R, W> {
    reader: R,
    writer: W,
}

pub struct RW(pub ReadWrite<PipeReader, PipeWriter>);

impl RW {
    pub fn create() -> Option<Self> {
        let (reader, writer) = os_pipe::pipe().ok()?;
        Some(RW(ReadWrite { reader, writer }))
    }
}

impl PreImageOracle {
    pub fn create(hp_opt: &Option<HostProgram>) -> PreImageOracle {
        let host_program = hp_opt.as_ref().expect("No host program given");

        let mut cmd = Command::new(host_program.name.to_string());
        cmd.args(&host_program.arguments);

        let p_client = RW::create().expect("");
        let p_oracle = RW::create().expect("");
        let h_client = RW::create().expect("");
        let h_oracle = RW::create().expect("");

        // file descriptors 0, 1, 2 respectively correspond to the inherited stdin,
        // stdout, stderr.
        // We need to map 3, 4, 5, 6 in the child process
        let RW(ReadWrite {
            reader: h_reader,
            writer: h_writer,
        }) = h_oracle;
        let RW(ReadWrite {
            reader: p_reader,
            writer: p_writer,
        }) = p_oracle;

        // Use constant defined
        cmd.fd_mappings(vec![
            FdMapping {
                parent_fd: h_reader.as_raw_fd(),
                child_fd: HINT_CLIENT_READ_FD,
            },
            FdMapping {
                parent_fd: h_writer.as_raw_fd(),
                child_fd: HINT_CLIENT_WRITE_FD,
            },
            FdMapping {
                parent_fd: p_reader.as_raw_fd(),
                child_fd: PREIMAGE_CLIENT_READ_FD,
            },
            FdMapping {
                parent_fd: p_writer.as_raw_fd(),
                child_fd: PREIMAGE_CLIENT_WRITE_FD,
            },
        ])
        .unwrap_or_else(|_| panic!("Could not map file descriptors to server process"));

        PreImageOracle {
            cmd,
            oracle_client: p_client,
            hint_writer: h_client,
        }
    }

    pub fn start(&mut self) -> Child {
        // Spawning inherits the current process's stdin/stdout/stderr descriptors
        self.cmd
            .spawn()
            .expect("Could not spawn pre-image oracle process")
    }
}
