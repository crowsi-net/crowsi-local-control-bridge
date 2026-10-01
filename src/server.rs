use std::{
    io::ErrorKind,
    sync::atomic::{AtomicBool, Ordering},
    thread,
};
use std::{os::unix::net::UnixStream, time::Duration};

use crate::{BridgeError, DispatchTicket, LocalControlBridge, PrivateUnixListener, TrustedClock};

/// Receives only requests already consumed by the bridge's durable gate.
pub trait AuthorizedOperationHandler {
    /// Handles the operation on the same attested stream.
    ///
    /// # Errors
    ///
    /// Must fail closed for invalid operation framing or downstream state.
    fn handle(
        &mut self,
        ticket: DispatchTicket,
        stream: &mut UnixStream,
    ) -> Result<(), BridgeError>;
}

/// Composes the bridge with one purpose-specific local operation handler.
pub struct LocalControlServer<C, H> {
    socket: PrivateUnixListener,
    bridge: LocalControlBridge<C>,
    handler: H,
    io_timeout: Duration,
}

impl<C: TrustedClock, H: AuthorizedOperationHandler> LocalControlServer<C, H> {
    #[must_use]
    pub const fn new(
        socket: PrivateUnixListener,
        bridge: LocalControlBridge<C>,
        handler: H,
        io_timeout: Duration,
    ) -> Self {
        Self {
            socket,
            bridge,
            handler,
            io_timeout,
        }
    }

    /// Accepts and handles one bounded operation.
    ///
    /// # Errors
    ///
    /// Rejects transport, authorization, replay, and handler failures.
    pub fn serve_one(&mut self) -> Result<(), BridgeError> {
        let (mut stream, _) = self
            .socket
            .listener()
            .accept()
            .map_err(|_| BridgeError::Transport)?;
        self.handle_stream(&mut stream)
    }

    /// Handles connections until the caller's signal-safe shutdown flag is set.
    ///
    /// # Errors
    ///
    /// Stops on listener failures other than interruption or an empty queue.
    pub fn serve_until(&mut self, shutdown: &AtomicBool) -> Result<(), BridgeError> {
        self.socket
            .listener()
            .set_nonblocking(true)
            .map_err(|_| BridgeError::Transport)?;
        let result = self.nonblocking_loop(shutdown);
        let restored = self.socket.listener().set_nonblocking(false);
        if restored.is_err() {
            return Err(BridgeError::Transport);
        }
        result
    }

    /// Handles an accepted stream after applying finite I/O deadlines.
    ///
    /// # Errors
    ///
    /// Rejects missing deadlines, authorization failures, and handler errors.
    pub fn handle_stream(&mut self, stream: &mut UnixStream) -> Result<(), BridgeError> {
        if self.io_timeout.is_zero() || self.io_timeout > Duration::from_secs(30) {
            return Err(BridgeError::Contract);
        }
        stream
            .set_read_timeout(Some(self.io_timeout))
            .map_err(|_| BridgeError::Transport)?;
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|_| BridgeError::Transport)?;
        let ticket = self.bridge.authorize_unix_stream(stream)?;
        self.handler.handle(ticket, stream)
    }

    #[must_use]
    pub fn socket_path(&self) -> &std::path::Path {
        self.socket.path()
    }

    fn nonblocking_loop(&mut self, shutdown: &AtomicBool) -> Result<(), BridgeError> {
        while !shutdown.load(Ordering::Acquire) {
            match self.socket.listener().accept() {
                Ok((mut stream, _)) => self.handle_stream(&mut stream)?,
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Err(BridgeError::Transport),
            }
        }
        Ok(())
    }
}
