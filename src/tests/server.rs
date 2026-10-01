use std::{
    io::Write,
    os::unix::net::UnixStream,
    sync::atomic::AtomicBool,
    sync::{Arc, Mutex},
    time::Duration,
};

use super::support::fixture_for_peer;
use crate::{
    AuthorizedOperationHandler, BridgeError, DispatchTicket, IpcAuthorizationEnvelopeV2,
    LocalControlServer, PrivateUnixListener, peer::attest_unix_peer,
};

struct Capture(Arc<Mutex<Vec<DispatchTicket>>>);

impl AuthorizedOperationHandler for Capture {
    fn handle(
        &mut self,
        ticket: DispatchTicket,
        _stream: &mut UnixStream,
    ) -> Result<(), BridgeError> {
        self.0
            .lock()
            .map_err(|_| BridgeError::Storage)?
            .push(ticket);
        Ok(())
    }
}

#[test]
fn server_dispatches_only_after_authorization_is_consumed() {
    let (mut server_stream, mut client) = UnixStream::pair().expect("attested stream");
    let Ok(peer) = attest_unix_peer(&server_stream) else {
        return;
    };
    let fixture = fixture_for_peer(peer);
    let path = fixture.root.path().join("control.sock");
    let socket = PrivateUnixListener::bind(&path).expect("private socket");
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut server = LocalControlServer::new(
        socket,
        fixture.bridge,
        Capture(Arc::clone(&captured)),
        Duration::from_secs(1),
    );
    let envelope = IpcAuthorizationEnvelopeV2 {
        schema: "crowsi://local-control/ipc-envelope/v2".into(),
        request: fixture.request,
        authorization: fixture.authorization,
        sender_proof: fixture.proof,
    };
    let body = serde_json::to_vec(&envelope).expect("envelope");
    client
        .write_all(&u32::try_from(body.len()).expect("bounded").to_be_bytes())
        .expect("length");
    client.write_all(&body).expect("body");
    assert_eq!(
        attest_unix_peer(&server_stream).expect("stable peer"),
        fixture.peer
    );
    server_stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read deadline");
    server_stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .expect("write deadline");
    assert_eq!(
        attest_unix_peer(&server_stream).expect("peer after deadlines"),
        fixture.peer
    );

    server
        .handle_stream(&mut server_stream)
        .expect("authorized dispatch");
    let tickets = captured.lock().expect("captured");
    assert_eq!(tickets.len(), 1);
    assert_eq!(tickets[0].pairwise_subject, "pairwise:operator");
}

#[test]
fn server_rejects_unbounded_deadline_before_reading() {
    let (probe, _) = UnixStream::pair().expect("peer probe");
    let Ok(peer) = attest_unix_peer(&probe) else {
        return;
    };
    let fixture = fixture_for_peer(peer);
    let path = fixture.root.path().join("control.sock");
    let socket = PrivateUnixListener::bind(path).expect("private socket");
    let mut server = LocalControlServer::new(
        socket,
        fixture.bridge,
        Capture(Arc::new(Mutex::new(Vec::new()))),
        Duration::ZERO,
    );
    let (mut stream, _) = UnixStream::pair().expect("stream");
    assert_eq!(
        server.handle_stream(&mut stream),
        Err(BridgeError::Contract)
    );
}

#[test]
fn server_shutdown_flag_stops_without_accepting_or_leaving_a_socket() {
    let (probe, _) = UnixStream::pair().expect("peer probe");
    let Ok(peer) = attest_unix_peer(&probe) else {
        return;
    };
    let fixture = fixture_for_peer(peer);
    let path = fixture.root.path().join("control.sock");
    let socket = PrivateUnixListener::bind(&path).expect("private socket");
    let mut server = LocalControlServer::new(
        socket,
        fixture.bridge,
        Capture(Arc::new(Mutex::new(Vec::new()))),
        Duration::from_secs(1),
    );
    let shutdown = AtomicBool::new(true);
    server.serve_until(&shutdown).expect("clean shutdown");
    drop(server);
    assert!(!path.exists());
}
