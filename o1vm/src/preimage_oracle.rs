use crate::cannon::{
    Hint, HostProgram, Preimage, HINT_CLIENT_READ_FD, HINT_CLIENT_WRITE_FD,
    PREIMAGE_CLIENT_READ_FD, PREIMAGE_CLIENT_WRITE_FD,
};
use command_fds::{CommandFdExt, FdMapping};
use log::debug;
use os_pipe::{PipeReader, PipeWriter};
use std::{
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::{Child, Command},
};

pub struct PreImageOracle {
    pub cmd: Command,
    pub oracle_client: RW,
    pub oracle_server: RW,
    pub hint_client: RW,
    pub hint_server: RW,
}

pub trait PreImageOracleT {
    fn get_preimage(&mut self, key: [u8; 32]) -> Preimage;

    fn hint(&mut self, hint: Hint);
}

pub struct ReadWrite<R, W> {
    pub reader: R,
    pub writer: W,
}

pub struct RW(pub ReadWrite<PipeReader, PipeWriter>);

// Here, we implement `os_pipe::pipe` in a way that allows us to pass flags. In particular, we
// don't pass the `CLOEXEC` flag, because we want these pipes to survive an exec, and we set
// `DIRECT` to handle writes as single atomic operations (up to splitting at the buffer size).
// This fixes the IPC hangs. This is bad, but the hang is worse.

#[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "haiku", windows)))]
fn create_pipe() -> std::io::Result<(PipeReader, PipeWriter)> {
    let mut fds: [libc::c_int; 2] = [0; 2];
    let res = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_DIRECT) };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }
    unsafe {
        Ok((
            PipeReader::from_raw_fd(fds[0]),
            PipeWriter::from_raw_fd(fds[1]),
        ))
    }
}

#[cfg(any(target_os = "ios", target_os = "macos", target_os = "haiku"))]
pub fn create_pipe() -> std::io::Result<(PipeReader, PipeWriter)> {
    let mut fds: [libc::c_int; 2] = [0; 2];
    let res = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // It appears that Mac and friends don't have DIRECT. Oh well. Don't use a Mac.
    let res = unsafe { libc::fcntl(fds[0], libc::F_SETFD, 0) };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let res = unsafe { libc::fcntl(fds[1], libc::F_SETFD, 0) };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }
    unsafe {
        Ok((
            PipeReader::from_raw_fd(fds[0]),
            PipeWriter::from_raw_fd(fds[1]),
        ))
    }
}

#[cfg(windows)]
pub fn create_pipe() -> std::io::Result<(PipeReader, PipeWriter)> {
    os_pipe::pipe()
}

// Create bidirectional channel between A and B
//
// Schematically we create 2 unidirectional pipes and creates 2 structures made
// by taking the writer from one and the reader from the other.
//
//     A                     B
//     |     ar  <---- bw    |
//     |     aw  ----> br    |
//
pub fn create_bidirectional_channel() -> Option<(RW, RW)> {
    let (ar, bw) = create_pipe().ok()?;
    let (br, aw) = create_pipe().ok()?;
    Some((
        RW(ReadWrite {
            reader: ar,
            writer: aw,
        }),
        RW(ReadWrite {
            reader: br,
            writer: bw,
        }),
    ))
}

impl PreImageOracle {
    pub fn create(host_program: HostProgram) -> PreImageOracle {
        let mut cmd = Command::new(&host_program.name);
        cmd.args(&host_program.arguments);

        let (oracle_client, oracle_server) =
            create_bidirectional_channel().expect("Could not create bidirectional oracle channel");
        let (hint_client, hint_server) =
            create_bidirectional_channel().expect("Could not create bidirectional hint channel");

        // file descriptors 0, 1, 2 respectively correspond to the inherited stdin,
        // stdout, stderr.
        // We need to map 3, 4, 5, 6 in the child process
        cmd.fd_mappings(vec![
            FdMapping {
                parent_fd: unsafe { OwnedFd::from_raw_fd(hint_server.0.writer.as_raw_fd()) },
                child_fd: HINT_CLIENT_WRITE_FD,
            },
            FdMapping {
                parent_fd: unsafe { OwnedFd::from_raw_fd(hint_server.0.reader.as_raw_fd()) },
                child_fd: HINT_CLIENT_READ_FD,
            },
            FdMapping {
                parent_fd: unsafe { OwnedFd::from_raw_fd(oracle_server.0.writer.as_raw_fd()) },
                child_fd: PREIMAGE_CLIENT_WRITE_FD,
            },
            FdMapping {
                parent_fd: unsafe { OwnedFd::from_raw_fd(oracle_server.0.reader.as_raw_fd()) },
                child_fd: PREIMAGE_CLIENT_READ_FD,
            },
        ])
        .unwrap_or_else(|_| panic!("Could not map file descriptors to preimage server process"));

        PreImageOracle {
            cmd,
            oracle_client,
            oracle_server,
            hint_client,
            hint_server,
        }
    }

    pub fn start(&mut self) -> Child {
        // Spawning inherits the current process's stdin/stdout/stderr descriptors
        self.cmd
            .spawn()
            .expect("Could not spawn pre-image oracle process")
    }
}

pub struct NullPreImageOracle;

impl PreImageOracleT for NullPreImageOracle {
    fn get_preimage(&mut self, _key: [u8; 32]) -> Preimage {
        panic!("No preimage oracle specified for preimage retrieval");
    }

    fn hint(&mut self, _hint: Hint) {
        panic!("No preimage oracle specified for hints");
    }
}

impl PreImageOracleT for PreImageOracle {
    // The preimage protocol goes as follows
    // 1. Ask for data through a key
    // 2. Get the answers in the following format
    //      +------------+--------------------+
    //      | length <8> | pre-image <length> |
    //      +---------------------------------+
    //   a. a 64-bit integer indicating the length of the actual data
    //   b. the preimage data, with a size of <length> bits
    fn get_preimage(&mut self, key: [u8; 32]) -> Preimage {
        let RW(ReadWrite { reader, writer }) = &mut self.oracle_client;

        let r = writer.write_all(&key);
        assert!(r.is_ok());
        let r = writer.flush();
        assert!(r.is_ok());

        debug!("Reading response");
        let mut buf = [0_u8; 8];
        let resp = reader.read_exact(&mut buf);
        assert!(resp.is_ok());

        debug!("Extracting contents");
        let length = u64::from_be_bytes(buf);
        let mut preimage = vec![0_u8; length as usize];
        let resp = reader.read_exact(&mut preimage);

        assert!(resp.is_ok());

        debug!(
            "Got preimage of length {}\n {}",
            preimage.len(),
            hex::encode(&preimage)
        );
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
    // 2. Get back a single ack byte informing the hint has been processed.
    fn hint(&mut self, hint: Hint) {
        let RW(ReadWrite { reader, writer }) = &mut self.hint_client;

        // Write hint request
        let mut hint_bytes = hint.get();
        let hint_length = hint_bytes.len();

        let mut msg: Vec<u8> = vec![];
        msg.append(&mut u64::to_be_bytes(hint_length as u64).to_vec());
        msg.append(&mut hint_bytes);

        let _ = writer.write(&msg);

        // Read single byte acknowledgment response
        let mut buf = [0_u8];
        // And do nothing with it anyway
        let _ = reader.read_exact(&mut buf);
    }
}

impl PreImageOracleT for Box<dyn PreImageOracleT> {
    fn get_preimage(&mut self, key: [u8; 32]) -> Preimage {
        self.as_mut().get_preimage(key)
    }

    fn hint(&mut self, hint: Hint) {
        self.as_mut().hint(hint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test that bidirectional channels work as expected
    // That is, after creating a pair (c0, c1)
    // 1. c1's reader can read what c0's writer produces
    // 2. c0's reader can read what c1's writer produces
    #[test]
    fn test_bidir_channels() {
        let (mut c0, mut c1) = create_bidirectional_channel().unwrap();

        // Send a single byte message
        let msg = [42_u8];
        let mut buf = [0_u8; 1];

        let writer_joiner = std::thread::spawn(move || {
            let r = c0.0.writer.write(&msg);
            assert!(r.is_ok());
        });

        let reader_joiner = std::thread::spawn(move || {
            let r = c1.0.reader.read_exact(&mut buf);
            assert!(r.is_ok());
            buf
        });

        // Retrieve the buffer from the reader
        let buf = reader_joiner.join().unwrap();
        // Ensure that the writer has completed
        writer_joiner.join().unwrap();

        // Check that we correctly read the single byte message
        assert_eq!(msg, buf);

        // Create a more structured message with the preimage format
        //      +------------+--------------------+
        //      | length <8> | pre-image <length> |
        //      +---------------------------------+
        //   Here we'll use a length of 2
        let msg2 = vec![42_u8, 43_u8];
        let len = msg2.len() as u64;
        let mut msg = u64::to_be_bytes(len).to_vec();
        msg.extend_from_slice(&msg2);

        // Write the message
        let writer_joiner = std::thread::spawn(move || {
            let r = c1.0.writer.write(&msg);
            assert!(r.is_ok());
            msg
        });

        // Read back the length from the other end of the bidirectionnal channel
        let reader_joiner = std::thread::spawn(move || {
            let mut response_vec = vec![];
            // We do a single read to mirror go, even though we should *really* do 2. 'Go' figure.
            let r = c0.0.reader.read_to_end(&mut response_vec);
            assert!(r.is_ok());

            let n = u64::from_be_bytes(response_vec[0..8].try_into().unwrap());

            let data = response_vec[8..(n + 8) as usize].to_vec();
            (n, data)
        });

        // Retrieve the data from the reader
        let (n, data) = reader_joiner.join().unwrap();

        // Ensure that the writer has completed
        writer_joiner.join().unwrap();

        // Check that the responses are equal
        assert_eq!(n, len);
        assert_eq!(data, msg2);
    }
}
