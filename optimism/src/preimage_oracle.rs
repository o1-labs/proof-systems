use crate::cannon::{
    Hint, HostProgram, Preimage, HINT_CLIENT_READ_FD, HINT_CLIENT_WRITE_FD,
    PREIMAGE_CLIENT_READ_FD, PREIMAGE_CLIENT_WRITE_FD,
};
use command_fds::{CommandFdExt, FdMapping};
use os_pipe::{PipeReader, PipeWriter};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::process::{Child, Command};

pub enum Key {
    Keccak([u8; 32]),
    Local([u8; 32]),
    Global([u8; 32]),
}

impl Key {
    pub fn contents(&self) -> [u8; 32] {
        use Key::*;
        match self {
            Keccak(v) => *v,
            Local(v) => *v,
            Global(v) => *v,
        }
    }

    pub fn typ(&self) -> u8 {
        use Key::*;
        match self {
            Keccak(_) => 2_u8,
            Local(_) => 1_u8,
            Global(_) => 3_u8,
        }
    }
}

pub struct PreImageOracle {
    pub cmd: Command,
    pub preimage_write: RW,
    pub preimage_read: RW,
    pub hint_write: RW,
    pub hint_read: RW,
}

pub struct ReadWrite<R, W> {
    pub reader: R,
    pub writer: W,
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

        let mut cmd = Command::new(&host_program.name);
        cmd.args(&host_program.arguments);

        let preimage_write = RW::create().expect("Could not create preimage write channel");
        let preimage_read = RW::create().expect("Could not create preimage read channel");

        let hint_write = RW::create().expect("Could not create hint write channel");
        let hint_read = RW::create().expect("Could not create hint read channel");

        // file descriptors 0, 1, 2 respectively correspond to the inherited stdin,
        // stdout, stderr.
        // We need to map 3, 4, 5, 6 in the child process
        cmd.fd_mappings(vec![
            FdMapping {
                parent_fd: hint_read.0.writer.as_raw_fd(),
                child_fd: HINT_CLIENT_WRITE_FD,
            },
            FdMapping {
                parent_fd: hint_write.0.reader.as_raw_fd(),
                child_fd: HINT_CLIENT_READ_FD,
            },
            FdMapping {
                parent_fd: preimage_read.0.writer.as_raw_fd(),
                child_fd: PREIMAGE_CLIENT_WRITE_FD,
            },
            FdMapping {
                parent_fd: preimage_write.0.reader.as_raw_fd(),
                child_fd: PREIMAGE_CLIENT_READ_FD,
            },
        ])
        .unwrap_or_else(|_| panic!("Could not map file descriptors to server process"));

        PreImageOracle {
            cmd,
            preimage_read,
            preimage_write,
            hint_read,
            hint_write,
        }
    }

    pub fn start(&mut self) -> Child {
        // Spawning inherits the current process's stdin/stdout/stderr descriptors
        self.cmd
            .spawn()
            .expect("Could not spawn pre-image oracle process")
    }

    // The preimage protocol goes as follows
    // 1. Ask for data through a key
    // 2. Get the answers in the following format
    //      +------------+--------------------+
    //      | length <8> | pre-image <length> |
    //      +---------------------------------+
    //   a. a 64-bit integer indicating the length of the actual data
    //   b. the preimage data, with a size of <length> bits
    pub fn get_preimage(&mut self, key: Key) -> Preimage {
        let RW(ReadWrite {
            reader: _,
            writer: preimage_writer,
        }) = &mut self.preimage_write;
        let RW(ReadWrite {
            reader: preimage_reader,
            writer: _,
        }) = &mut self.preimage_read;

        let key_contents = key.contents();
        let key_type = key.typ();

        let mut msg_key = vec![key_type];
        msg_key.extend_from_slice(&key_contents[1..31]);
        let _ = preimage_writer.write(&msg_key);

        let mut buf = [0_u8; 8];
        let _ = preimage_reader.read_exact(&mut buf);

        let length = u64::from_be_bytes(buf);
        let mut handle = preimage_reader.take(length);
        let mut preimage = vec![0_u8; length as usize];
        let _ = handle.read(&mut preimage);

        // We should have read exactly <length> bytes
        assert_eq!(preimage.len(), length as usize);

        Preimage::create(preimage)
    }

    // The hint protocol goes as follows:
    // 1. Write a hint request with the following byte-stream format
    //       +------------+---------------+
    //       | length <8> | hint <length> |
    //       +----------------------------+
    //
    // 2. Get back a single ack byte informing the the hint has been processed.
    pub fn hint(&mut self, hint: Hint) {
        let RW(ReadWrite {
            reader: _,
            writer: hint_writer,
        }) = &mut self.hint_write;
        let RW(ReadWrite {
            reader: hint_reader,
            writer: _,
        }) = &mut self.hint_read;

        // Write hint request
        let mut hint_bytes = hint.get();
        let hint_length = hint_bytes.len();

        let mut msg: Vec<u8> = vec![];
        msg.append(&mut u64::to_be_bytes(hint_length as u64).to_vec());
        msg.append(&mut hint_bytes);

        let _ = hint_writer.write(&msg);

        // Read single byte acknowledgment response
        let mut buf = [0_u8];
        let _ = hint_reader.read_exact(&mut buf);
    }
}

#[cfg(test)]
mod tests {

    // TODO
    #[test]
    fn test_preimage_get() {}
}
