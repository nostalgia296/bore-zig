# bore-zig

A Zig implementation of [bore](https://github.com/ekzhang/bore), a small TCP tunnel for exposing a local TCP port through a remote server.

## Build

Requires Zig 0.17.0 and a POSIX system with libc.

```sh
zig build -Doptimize=ReleaseFast
```

The executable is written to `zig-out/bin/bore`.

## Run

Start a server:

```sh
./zig-out/bin/bore server
```

Expose a local service:

```sh
./zig-out/bin/bore local 8000 --to bore.pub
```

Set `BORE_SECRET` on both sides to enable challenge-response authentication. Server options include `--min-port`, `--max-port`, `--bind-addr`, and `--bind-tunnels`; local options include `--local-host` and `--port`. Run `bore help` for complete usage.

## Tests

```sh
zig build test
```
