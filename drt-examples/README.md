# drt-examples

Sample DRT scripts that run inside the SGX enclave when an analyst invokes a
granted Digital Rights Token. Each script is a Rust crate compiled to
`wasm32-unknown-unknown`, with its SHA-256 pinned on-chain at DRT
registration time and re-verified on every fetch.

## Layout

```
drt-examples/
├── README.md         (this file)
└── mean/             canonical sample DRT
    ├── Cargo.toml
    ├── .cargo/config.toml   (sets default target = wasm32-unknown-unknown)
    ├── src/lib.rs
    └── dist/mean.wasm       (committed build artifact)
```

Future DRTs live as sibling crates (`drt-examples/<name>/`). They are not
part of the parent Cargo workspace — each is built standalone so its WASM
release profile does not leak into the SDK build. The shipped profile is
tuned for **runtime speed**, not file size (`opt-level = 3`, `lto = "fat"`,
single codegen unit, `panic = abort`). The wasm is fetched once, then
AOT-compiled to native by the enclave and cached on the encrypted FS, so
the wire size is a one-off and the native code cost is what matters.

## Trust contract

The enclave will run a DRT script only if its SHA-256 matches the
`code_hash` recorded in the on-chain `DrtConfig`. The pipeline:

1. Admin builds and publishes the `.wasm`.
2. Admin records `(code_repo_url, code_hash)` on-chain via pool creation.
3. Enclave fetches `code_repo_url`, SHA-256-checks the bytes against
   `code_hash` (see `relational-sdk/src/drt/verified_fetch.rs`), rejects on
   mismatch, caches verified bytes under `/data/drt-scripts/<hash>`.
4. Enclave loads the cached bytes into the `wasmtime` sandbox (see
   `relational-sdk/src/drt/runtime.rs`), AOT-compiles them once via
   Cranelift, caches the native artifact at
   `/data/drt-scripts/{hash}.wt37.cwasm`, and invokes the `run` export.

The cache is keyed by hash — the filename *is* the integrity claim, and the
runtime re-hashes the bytes on every read. The `.cwasm` suffix is
versioned by wasmtime release (`wt37`) so a runtime upgrade invalidates
stale artifacts automatically.

## Host ABI (zero-copy)

A DRT module exports two functions plus `memory` and imports one:

| Direction | Signature | Notes |
|---|---|---|
| export | `memory` | default linear memory; host reads/writes directly |
| export | `alloc(size: i32) -> i32` | bump allocator the host calls before `run` |
| export | `run(csv_ptr: i32, csv_len: i32, args_ptr: i32, args_len: i32, out_ptr_cell: i32, out_len_cell: i32) -> i32` | 0 = success, non-zero = script-level error |
| import | `env.host_log(src: i32, len: i32)` | best-effort diagnostic; no other imports |

Flow on every query:

1. Host calls `alloc(csv_len)`, then writes the CSV bytes into `memory` at
   the returned address.
2. Host calls `alloc(args_len)`, then writes the args JSON.
3. Host calls `alloc(8)` for two i32 output cells.
4. Host calls `run(csv_ptr, csv_len, args_ptr, args_len, out_ptr_cell, out_len_cell)`.
5. On return, the host reads two little-endian i32s from
   `(out_ptr_cell, out_len_cell)` to find the output blob in `memory`.

No JSON envelope — the CSV is delivered as raw bytes. `args` is a small
UTF-8 JSON object scoped to the DRT.

Output should be UTF-8 JSON. Errors should be `{"error": "..."}` with a
non-zero exit from `run`.

Sandbox limits enforced by the runtime: 600 MiB input, 4 MiB output, 1 GiB
guest memory cap, fuel cap (`2 × 10⁹ + 1000 × input_bytes` instructions),
120 s wall clock. No WASI, no filesystem, no clock — only `host_log`.

## Build

```bash
cd mean
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/drt_mean.wasm dist/mean.wasm
sha256sum dist/mean.wasm
```

Host-side tests (no wasm runtime needed):

```bash
cargo test --target x86_64-unknown-linux-gnu
```

End-to-end test through the enclave's wasmtime runtime against the
committed `dist/mean.wasm` lives at `relational-sdk/src/drt/runtime.rs`
(run with `cd .. && cargo test drt::`).

## Publish

The `code_repo_url` recorded on-chain must resolve to the exact bytes that
hashed to `code_hash`. Commit `dist/<name>.wasm` to the relational-sdk repo
so the URL

```
https://raw.githubusercontent.com/relational-network/relational-sdk/<ref>/drt-examples/<name>/dist/<name>.wasm
```

resolves to the same bytes `sha256sum` reports locally. Update the DRT
registry entry (in the dashboard) with the new hash whenever the script
changes — the enclave will refuse to run any script whose fetched bytes
don't match the on-chain hash.

The enclave only accepts URLs on `raw.githubusercontent.com` under the
`relational-network/*` owner (allowlist in
`relational-sdk/src/drt/verified_fetch.rs`).

## Adding a new DRT

1. Copy `mean/` to `drt-examples/<your-drt>/`.
2. Rename the crate in `Cargo.toml` (set `name = "drt-<your-drt>"`).
3. Implement `run()` against the host ABI above.
4. Build and commit `dist/<your-drt>.wasm`.
5. Add a registry entry on the dashboard side pointing at the raw URL and
   the SHA-256.
