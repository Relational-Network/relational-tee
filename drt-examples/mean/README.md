# `mean` — sample DRT

Computes the arithmetic mean of a numeric column from the pool's CSV data,
inside the enclave, with no host calls during execution beyond an optional
diagnostic `host_log`.

## Verified artifact

The committed binary is the canonical input to the enclave's verified-fetch
path. Pin and check this hash whenever you reproduce the build:

```
dist/mean.wasm
sha256: 78354066889df41ad7399d08f8667406e93db2e901b7c67e24da033b1c24b8f9
size:   15 445 bytes
```

The enclave AOT-compiles this module to a native `.cwasm` once at grant
time using wasmtime 37 (Cranelift). The compiled artifact is cached on the
Gramine encrypted FS at `/data/drt-scripts/{sha256}.wt37.cwasm`. The
`wt37` suffix is invalidated automatically when wasmtime is upgraded.

## Host ABI

The enclave runtime ([`relational-sdk/src/drt/runtime.rs`](../../src/drt/runtime.rs))
places the CSV and args JSON directly into this module's linear memory
before invoking `run` — no streaming, no JSON envelope.

### Exports this module provides

```text
memory                                      (default `memory` export)
alloc(size: i32) -> i32                     bump allocator the host calls
run(
    csv_ptr: i32, csv_len: i32,
    args_ptr: i32, args_len: i32,
    out_ptr_cell: i32, out_len_cell: i32,
) -> i32                                    0 = success, non-zero = script error
```

`run` writes the output JSON blob into `memory` (via the same bump
allocator) and stores its `(ptr, len)` as two little-endian i32s at the
addresses the host passed in.

### Imports this module needs

```text
env.host_log(ptr: i32, len: i32)
```

That's the only import. Everything else (CSV bytes, args bytes, output
buffer) flows through linear memory.

## Input

- `csv`: raw UTF-8 CSV, header row included. No JSON wrapping.
- `args`: small UTF-8 JSON object — `{"column": "<header name>"}`.

## Output

```json
{ "column": "value", "count": 1180, "skipped": 54, "mean": 71.5 }
```

`count` is the number of rows that contributed; `skipped` is the number of
rows whose target cell was missing, empty, or non-numeric. On failure:

```json
{ "error": "column 'foo' not in header" }
```

with a non-zero exit from `run`.

## Reproducing the build

```bash
cd relational-sdk/drt-examples/mean
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/drt_mean.wasm dist/mean.wasm
sha256sum dist/mean.wasm   # must match the hash above
```

The release profile is tuned for **speed**, not size:

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
overflow-checks = false
```

Rationale: the wasm file is fetched once per DRT (~15 KiB), then AOT-compiled
to native code that's cached on the encrypted FS and reused on every query.
The runtime cost matters; the wire size doesn't.

## Performance notes

The hot path is a single-pass byte-level CSV scanner. It avoids the slow
spots in the obvious `csv.lines().split(',').nth(col).parse::<f64>()`
formulation:

- **No per-row UTF-8 validation** — operates on `&[u8]`.
- **No `&str` allocations** — fields are byte slices into the input.
- **Fused header + body scan** — column index resolved once, then row scan
  counts commas to slice the target field directly.
- **Custom decimal `f64` parser** — supports `±int[.frac][e±N]`; skips
  `from_str`'s slow paths. Round-off is within a few ULPs, fine for an
  arithmetic mean.
- **Bump-only allocator** — Rust's `alloc::String`/`Vec` use a `GlobalAlloc`
  that never frees. The instance is short-lived; memory is recycled at
  next query.

## Running the host-side tests

```bash
cd relational-sdk/drt-examples/mean
cargo test --target x86_64-unknown-linux-gnu
```

The wasm-target build is the artifact; the host build exercises the same
pure-Rust scanner via `run_host`.

## Running the enclave runtime tests

From the `relational-sdk` crate, three tests in `src/drt/runtime.rs` load
this committed `dist/mean.wasm` and run it through wasmtime end-to-end:

```bash
cd relational-sdk
cargo test --release drt::runtime::tests
```
