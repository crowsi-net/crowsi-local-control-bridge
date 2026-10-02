# crowsi-local-control-bridge

Authenticate a local process and authorize its request before passing it to a protected service.

## What you can do

- Bind a Unix-stream request to peer and workload evidence.
- Validate exact action, resource and purpose.

## Current scope

The host supplies trust, policy and private socket placement. A reachable socket is not sufficient authorization.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
