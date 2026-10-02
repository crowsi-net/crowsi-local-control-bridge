# Using crowsi-local-control-bridge

Authenticate a local process and authorize its request before passing it to a protected service.

## Before you start

The host supplies trust, policy and private socket placement. A reachable socket is not sufficient authorization.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Bind a Unix-stream request to peer and workload evidence.
- Validate exact action, resource and purpose.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
