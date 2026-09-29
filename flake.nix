# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Nix is used at build time only: it pins every input and builds the static
# server binary and the OCI image, but never ships inside the image.
{
  description = "relational-tee: the IOB MicRes worker";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      rust-overlay,
    }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forSystems = f: lib.genAttrs systems (system: f (pkgsFor system));
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

      # The toolchain comes from rust-toolchain.toml, so Nix, CI and rustup
      # builds all use the same pinned compiler.
      toolchainFor =
        pkgs: targets:
        (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override { inherit targets; };

      # Commit time of the flake source, for reproducible timestamps. Only the
      # final package gets it: in the shared arguments it would change the
      # dependency and check derivations on every commit and defeat their cache.
      sourceDateEpoch = toString (self.lastModified or 1);

      commonArgs = craneLib: pkgs: {
        src = craneLib.cleanCargoSource ./.;
        strictDeps = true;
        buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.libiconv ];
      };

      # Checks and the dev shell use the host toolchain.
      nativeFor =
        pkgs:
        let
          craneLib = (crane.mkLib pkgs).overrideToolchain (toolchainFor pkgs [ ]);
          args = commonArgs craneLib pkgs;
          cargoArtifacts = craneLib.buildDepsOnly (args // { cargoExtraArgs = "--all-features"; });
          # Checks only report success; they don't need to keep their target dir.
          checkArgs = args // {
            inherit cargoArtifacts;
            doInstallCargoArtifacts = false;
          };
        in
        {
          inherit craneLib;
          checks = {
            fmt = craneLib.cargoFmt { inherit (args) src; };
            clippy = craneLib.cargoClippy (
              checkArgs // { cargoClippyExtraArgs = "--all-targets --all-features -- -D warnings"; }
            );
            clippy-release = craneLib.cargoClippy (
              checkArgs // { cargoClippyExtraArgs = "--all-targets -- -D warnings"; }
            );
            nextest = craneLib.cargoNextest checkArgs;
            nextest-dev = craneLib.cargoNextest (checkArgs // { cargoNextestExtraArgs = "--features dev"; });
          };
        };

      # A release binary statically linked against musl, built on Linux.
      serverFor =
        pkgs: features:
        let
          static = pkgs.pkgsStatic.stdenv;
          target = static.hostPlatform.rust.rustcTarget;
          targetEnv = lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] target);
          cc = "${static.cc}/bin/${static.cc.targetPrefix}cc";
          craneLib = (crane.mkLib pkgs).overrideToolchain (toolchainFor pkgs [ target ]);
          args = commonArgs craneLib pkgs // {
            nativeBuildInputs = [ static.cc ];
            cargoExtraArgs = "--locked" + lib.optionalString (features != "") " --features ${features}";
            doCheck = false;
            CARGO_BUILD_TARGET = target;
            "CARGO_TARGET_${targetEnv}_LINKER" = cc;
            "CC_${builtins.replaceStrings [ "-" ] [ "_" ] target}" = cc;
            HOST_CC = "${pkgs.stdenv.cc}/bin/cc";
            # Strip the build directory from paths embedded in the binary.
            preBuild = ''
              export CARGO_BUILD_RUSTFLAGS="-C target-feature=+crt-static --remap-path-prefix=$NIX_BUILD_TOP=/build"
            '';
          };
        in
        craneLib.buildPackage (
          args
          // {
            cargoArtifacts = craneLib.buildDepsOnly args;
            SOURCE_DATE_EPOCH = sourceDateEpoch;
          }
        );

      # /etc/passwd and /etc/group for the non-root user; the image has no shell.
      etcFor =
        pkgs:
        pkgs.runCommand "relational-tee-etc" { } ''
          mkdir -p $out/etc
          echo 'nonroot:x:65532:65532:nonroot:/nonexistent:/sbin/nologin' > $out/etc/passwd
          echo 'nonroot:x:65532:' > $out/etc/group
        '';

      imageFor =
        pkgs: server:
        pkgs.dockerTools.buildLayeredImage {
          name = "relational-tee";
          tag = "latest";
          contents = [
            server
            pkgs.cacert
            (etcFor pkgs)
          ];
          config = {
            Entrypoint = [ "/bin/relational-tee" ];
            User = "65532:65532";
            WorkingDir = "/";
            ExposedPorts."8443/tcp" = { };
            Env = [ "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" ];
          };
        };
    in
    {
      packages = {
        x86_64-linux =
          let
            pkgs = pkgsFor "x86_64-linux";
            server = serverFor pkgs "";
          in
          {
            inherit server;
            image = imageFor pkgs server;
            default = server;
          };
        aarch64-linux =
          let
            pkgs = pkgsFor "aarch64-linux";
          in
          {
            image-dev = imageFor pkgs (serverFor pkgs "dev");
          };
      };

      checks = forSystems (pkgs: (nativeFor pkgs).checks);

      devShells = forSystems (pkgs: {
        default = (nativeFor pkgs).craneLib.devShell {
          packages = with pkgs; [
            cargo-nextest
            cargo-audit
            bacon
            just
            sccache
            azurite
            mkcert
            actionlint
          ];
          RUSTC_WRAPPER = "sccache";
        };
      });

      formatter = forSystems (pkgs: pkgs.nixfmt);
    };
}
