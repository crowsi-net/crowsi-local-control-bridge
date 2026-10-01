use std::{
    io::{ErrorKind, Read},
    os::{fd::AsFd, unix::net::UnixStream},
    time::{Duration, Instant},
};

use nix::poll::{PollFd, PollFlags, poll};

use crate::BridgeError;

pub(crate) fn frame(
    stream: &mut UnixStream,
    timeout: Duration,
    maximum: usize,
) -> Result<Vec<u8>, BridgeError> {
    if timeout.is_zero() || timeout > Duration::from_mins(1) {
        return Err(BridgeError::Time);
    }
    stream
        .set_nonblocking(true)
        .map_err(|_| BridgeError::Transport)?;
    let deadline = Instant::now() + timeout;
    let mut encoded_length = [0_u8; 4];
    read_exact(stream, &mut encoded_length, deadline)?;
    let length =
        usize::try_from(u32::from_be_bytes(encoded_length)).map_err(|_| BridgeError::Contract)?;
    if length == 0 || length > maximum {
        return Err(BridgeError::Contract);
    }
    let mut value = vec![0_u8; length];
    read_exact(stream, &mut value, deadline)?;
    Ok(value)
}

fn read_exact(
    stream: &mut UnixStream,
    mut value: &mut [u8],
    deadline: Instant,
) -> Result<(), BridgeError> {
    while !value.is_empty() {
        match stream.read(value) {
            Ok(0) => return Err(BridgeError::Transport),
            Ok(count) => value = &mut value[count..],
            Err(error) if error.kind() == ErrorKind::WouldBlock => wait(stream, deadline)?,
            Err(_) => return Err(BridgeError::Transport),
        }
    }
    Ok(())
}

fn wait(stream: &UnixStream, deadline: Instant) -> Result<(), BridgeError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(BridgeError::Time)?;
    let timeout = u16::try_from(remaining.as_millis().clamp(1, u128::from(u16::MAX)))
        .map_err(|_| BridgeError::Time)?;
    let mut descriptors = [PollFd::new(stream.as_fd(), PollFlags::POLLIN)];
    let ready = poll(&mut descriptors, timeout).map_err(|_| BridgeError::Transport)?;
    if ready == 0 {
        return Err(BridgeError::Time);
    }
    let events = descriptors[0].revents().unwrap_or(PollFlags::empty());
    if events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
        return Err(BridgeError::Transport);
    }
    Ok(())
}
