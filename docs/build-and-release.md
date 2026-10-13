# Build and release

## The Nix build

`flake.nix` pins nixpkgs and builds with crane, taking the toolchain from `rust-toolchain.toml`:

- `packages.x86_64-linux.server`: the release binary, statically linked against musl, with mimalloc as its allocator. `SOURCE_DATE_EPOCH` comes from the commit, and build paths are remapped out of the binary.
- `packages.x86_64-linux.image`: an OCI image containing only the binary, a pinned CA bundle and an `/etc/passwd` entry for the non-root user 65532. It has no shell, package manager or Nix. The entrypoint is `/bin/relational-tee`, on port 8443.
- `packages.aarch64-linux.image-dev`: the same image with the `dev` feature, for local container stacks on Apple Silicon.
- `checks`: rustfmt, clippy and nextest, run by `nix flake check`.

## CI

`.github/workflows/ci.yml` runs on every pull request and push to `main`, except those that change only documentation (Markdown files, `docs/` and `LICENSE`). Every job gets its toolchain from the flake:

- **Gates:** `just check` in the dev shell (rustfmt, clippy, the tests in the release and dev configurations, the banned-crate check, `cargo audit` and OSV-Scanner), then the OpenAPI document, published as the run's `openapi` artifact. CI fails if the `rsa` crate (RUSTSEC-2023-0071) or OpenSSL enters the dependency graph.
- **`nix flake check`.**
- **Chain tests:** `just chain-test`, against a local Surfpool network.
- **Reproducibility:** the x86_64 image is built on two runners and the two builds are compared; if they differ, diffoscope's report is uploaded.

## Publishing

On a push to `main`, once every job passes, CI pushes the image to GHCR as `ghcr.io/relational-network/relational-tee:<commit>`, with a build provenance attestation. If the repository holds a deployment's dispatch secrets, CI then starts that deployment's staging workflow with the commit and the image digest; the repository itself names no deployment. A documentation-only change publishes nothing.

To check that a running deployment runs a given commit, see [`deploy/README.md`](../deploy/README.md).
