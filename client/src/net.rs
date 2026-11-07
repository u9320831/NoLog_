use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Taille maximale d'un message TCP encadré.
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

/// Taille maximale d'un datagramme UDP IPv4/IPv6 utilisable par l'API.
pub const MAX_DATAGRAM_SIZE: usize = 65_507;

#[derive(Debug)]
pub enum NetworkError {
    Io(io::Error),
    FrameTooLarge,
    InvalidFrameLength,
    NotConnected,
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "network I/O error: {error}"),
            Self::FrameTooLarge => write!(f, "network frame is too large"),
            Self::InvalidFrameLength => write!(f, "invalid network frame length"),
            Self::NotConnected => write!(f, "UDP socket is not connected"),
        }
    }
}

impl std::error::Error for NetworkError {}

impl From<io::Error> for NetworkError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Façade réseau du client.
///
/// Les sockets restent des sockets Windows standard et leurs métadonnées sont
/// donc visibles par le système et les outils d'administration réseau.
#[derive(Debug, Default, Clone, Copy)]
pub struct NetworkInterface;

impl NetworkInterface {
    pub const fn new() -> Self {
        Self
    }

    pub fn connect_tcp<A: ToSocketAddrs>(
        &self,
        remote: A,
        timeout: Duration,
    ) -> Result<TcpConnection, NetworkError> {
        TcpConnection::connect(remote, timeout)
    }

    pub fn bind_udp<A: ToSocketAddrs>(&self, local: A) -> Result<UdpConnection, NetworkError> {
        UdpConnection::bind(local)
    }
}

/// Connexion TCP avec un préfixe de longueur big-endian par message.
#[derive(Debug)]
pub struct TcpConnection {
    stream: TcpStream,
}

impl TcpConnection {
    pub fn connect<A: ToSocketAddrs>(remote: A, timeout: Duration) -> Result<Self, NetworkError> {
        let mut last_error = None;

        for address in remote.to_socket_addrs()? {
            match TcpStream::connect_timeout(&address, timeout) {
                Ok(stream) => return Ok(Self { stream }),
                Err(error) => last_error = Some(error),
            }
        }

        Err(NetworkError::Io(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no socket address resolved")
        })))
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        Self { stream }
    }

    pub fn send_frame(&mut self, payload: &[u8]) -> Result<(), NetworkError> {
        let length = u32::try_from(payload.len()).map_err(|_| NetworkError::FrameTooLarge)?;
        if payload.len() > MAX_FRAME_SIZE {
            return Err(NetworkError::FrameTooLarge);
        }

        self.stream.write_all(&length.to_be_bytes())?;
        self.stream.write_all(payload)?;
        Ok(())
    }

    pub fn receive_frame(&mut self) -> Result<Vec<u8>, NetworkError> {
        let mut length_bytes = [0u8; 4];
        self.stream.read_exact(&mut length_bytes)?;
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length > MAX_FRAME_SIZE {
            return Err(NetworkError::FrameTooLarge);
        }

        let mut payload = vec![0u8; length];
        self.stream.read_exact(&mut payload)?;
        Ok(payload)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), NetworkError> {
        self.stream.set_read_timeout(timeout)?;
        Ok(())
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), NetworkError> {
        self.stream.set_write_timeout(timeout)?;
        Ok(())
    }

    pub fn local_addr(&self) -> Result<SocketAddr, NetworkError> {
        Ok(self.stream.local_addr()?)
    }

    pub fn peer_addr(&self) -> Result<SocketAddr, NetworkError> {
        Ok(self.stream.peer_addr()?)
    }
}

/// Socket UDP. Les limites de datagrammes sont conservées par l'API.
#[derive(Debug)]
pub struct UdpConnection {
    socket: UdpSocket,
    peer: Option<SocketAddr>,
}

impl UdpConnection {
    pub fn bind<A: ToSocketAddrs>(local: A) -> Result<Self, NetworkError> {
        Ok(Self {
            socket: UdpSocket::bind(local)?,
            peer: None,
        })
    }

    pub fn connect<A: ToSocketAddrs>(&mut self, remote: A) -> Result<(), NetworkError> {
        self.socket.connect(remote)?;
        self.peer = Some(self.socket.peer_addr()?);
        Ok(())
    }

    pub fn send(&self, payload: &[u8]) -> Result<usize, NetworkError> {
        if payload.len() > MAX_DATAGRAM_SIZE {
            return Err(NetworkError::FrameTooLarge);
        }
        if self.peer.is_none() {
            return Err(NetworkError::NotConnected);
        }
        Ok(self.socket.send(payload)?)
    }

    pub fn send_to<A: ToSocketAddrs>(
        &self,
        payload: &[u8],
        remote: A,
    ) -> Result<usize, NetworkError> {
        if payload.len() > MAX_DATAGRAM_SIZE {
            return Err(NetworkError::FrameTooLarge);
        }
        Ok(self.socket.send_to(payload, remote)?)
    }

    pub fn receive(&self) -> Result<Vec<u8>, NetworkError> {
        let mut buffer = vec![0u8; MAX_DATAGRAM_SIZE];
        let length = self.socket.recv(&mut buffer)?;
        buffer.truncate(length);
        Ok(buffer)
    }

    pub fn receive_from(&self) -> Result<(Vec<u8>, SocketAddr), NetworkError> {
        let mut buffer = vec![0u8; MAX_DATAGRAM_SIZE];
        let (length, remote) = self.socket.recv_from(&mut buffer)?;
        buffer.truncate(length);
        Ok((buffer, remote))
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), NetworkError> {
        self.socket.set_read_timeout(timeout)?;
        Ok(())
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), NetworkError> {
        self.socket.set_write_timeout(timeout)?;
        Ok(())
    }

    pub fn local_addr(&self) -> Result<SocketAddr, NetworkError> {
        Ok(self.socket.local_addr()?)
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }
}
