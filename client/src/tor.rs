use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::net::{NetworkError, TcpConnection};

const MAX_CONTROL_REPLY: usize = 4096;
const MAX_HOST_LENGTH: usize = 255;

#[derive(Debug)]
pub enum TorError {
    Io(io::Error),
    Network(NetworkError),
    Protocol(&'static str),
    ControlRejected,
}

impl std::fmt::Display for TorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "Tor I/O error: {error}"),
            Self::Network(error) => write!(f, "Tor network error: {error}"),
            Self::Protocol(message) => write!(f, "Tor SOCKS5 protocol error: {message}"),
            Self::ControlRejected => write!(f, "Tor ControlPort rejected the command"),
        }
    }
}

impl std::error::Error for TorError {}

impl From<io::Error> for TorError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<NetworkError> for TorError {
    fn from(error: NetworkError) -> Self {
        Self::Network(error)
    }
}

/// Configuration du transport Tor. Le proxy est explicitement opt-in.
#[derive(Debug, Clone)]
pub struct TorProxyConfig {
    pub socks_addr: SocketAddr,
    pub control_addr: Option<SocketAddr>,
    pub control_cookie_path: Option<PathBuf>,
    pub timeout: Duration,
    pub slow_threshold: Duration,
    pub newnym_cooldown: Duration,
}

impl TorProxyConfig {
    pub fn local_default() -> Self {
        Self {
            socks_addr: SocketAddr::from(([127, 0, 0, 1], 9050)),
            control_addr: None,
            control_cookie_path: None,
            timeout: Duration::from_secs(10),
            slow_threshold: Duration::from_secs(8),
            newnym_cooldown: Duration::from_secs(60),
        }
    }
}

/// Transport TCP via Tor SOCKS5.
///
/// Les connexions restent visibles localement vers Tor. Ce composant ne fournit
/// pas de dissimulation vis-à-vis de l'administrateur de la machine.
pub struct TorProxy {
    config: TorProxyConfig,
    last_newnym: Mutex<Option<Instant>>,
}

impl TorProxy {
    pub fn new(config: TorProxyConfig) -> Self {
        Self {
            config,
            last_newnym: Mutex::new(None),
        }
    }

    pub fn config(&self) -> &TorProxyConfig {
        &self.config
    }

    pub fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpConnection, TorError> {
        if host.is_empty() || host.len() > MAX_HOST_LENGTH || host.as_bytes().contains(&0) {
            return Err(TorError::Protocol("invalid target host"));
        }

        let started = Instant::now();
        let first = self.connect_once(host, port);
        let slow = started.elapsed() >= self.config.slow_threshold;

        if slow && self.request_newnym_if_allowed()? {
            return Ok(self.connect_once(host, port)?);
        }

        Ok(first?)
    }

    fn connect_once(&self, host: &str, port: u16) -> Result<TcpConnection, TorError> {
        let mut stream = TcpStream::connect_timeout(&self.config.socks_addr, self.config.timeout)?;
        stream.set_read_timeout(Some(self.config.timeout))?;
        stream.set_write_timeout(Some(self.config.timeout))?;

        stream.write_all(&[0x05, 0x01, 0x00])?;
        let mut method_reply = [0u8; 2];
        stream.read_exact(&mut method_reply)?;
        if method_reply != [0x05, 0x00] {
            return Err(TorError::Protocol(
                "Tor SOCKS5 proxy requires unsupported authentication",
            ));
        }

        let host_bytes = host.as_bytes();
        let mut request = Vec::with_capacity(7 + host_bytes.len());
        request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
        request.extend_from_slice(host_bytes);
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request)?;

        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply)?;
        if reply[0] != 0x05 {
            return Err(TorError::Protocol("invalid SOCKS5 version"));
        }
        if reply[1] != 0x00 {
            return Err(TorError::Protocol("Tor SOCKS5 connection rejected"));
        }

        match reply[3] {
            0x01 => {
                let mut address = [0u8; 4];
                stream.read_exact(&mut address)?;
            }
            0x03 => {
                let mut length = [0u8; 1];
                stream.read_exact(&mut length)?;
                let mut address = vec![0u8; length[0] as usize];
                stream.read_exact(&mut address)?;
            }
            0x04 => {
                let mut address = [0u8; 16];
                stream.read_exact(&mut address)?;
            }
            _ => return Err(TorError::Protocol("invalid SOCKS5 address type")),
        }

        let mut bound_port = [0u8; 2];
        stream.read_exact(&mut bound_port)?;
        Ok(TcpConnection::from_stream(stream))
    }

    fn request_newnym_if_allowed(&self) -> Result<bool, TorError> {
        let (Some(control_addr), Some(cookie_path)) = (
            self.config.control_addr,
            self.config.control_cookie_path.as_ref(),
        ) else {
            return Ok(false);
        };

        {
            let mut last = self
                .last_newnym
                .lock()
                .map_err(|_| TorError::Protocol("NEWNYM limiter poisoned"))?;
            if last.is_some_and(|value| value.elapsed() < self.config.newnym_cooldown) {
                return Ok(false);
            }
            *last = Some(Instant::now());
        }

        let cookie_bytes = fs::read(cookie_path)?;
        let cookie: Zeroizing<[u8; 32]> = Zeroizing::new(
            cookie_bytes
                .try_into()
                .map_err(|_| TorError::Protocol("Tor control cookie must be 32 bytes"))?,
        );

        let mut control = TcpStream::connect_timeout(&control_addr, self.config.timeout)?;
        control.set_read_timeout(Some(self.config.timeout))?;
        control.set_write_timeout(Some(self.config.timeout))?;

        let cookie_hex = to_hex(cookie.as_ref());
        write_control_command(&mut control, &format!("AUTHENTICATE {cookie_hex}"))?;
        write_control_command(&mut control, "SIGNAL NEWNYM")?;
        Ok(true)
    }
}

fn write_control_command(stream: &mut TcpStream, command: &str) -> Result<(), TorError> {
    stream.write_all(command.as_bytes())?;
    stream.write_all(b"\r\n")?;

    let mut reply = Vec::with_capacity(64);
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        reply.push(byte[0]);
        if reply.len() > MAX_CONTROL_REPLY {
            return Err(TorError::Protocol("ControlPort reply too large"));
        }
        if byte[0] == b'\n' {
            let text = String::from_utf8_lossy(&reply);
            if text.starts_with("250 ") {
                return Ok(());
            }
            if text.starts_with('4') || text.starts_with('5') {
                return Err(TorError::ControlRejected);
            }
            reply.clear();
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}
