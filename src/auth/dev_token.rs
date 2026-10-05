// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The dev token signing key (dev builds only).
//!
//! Dev builds trust one key besides Entra ID's: `entra-signing-key.pem` in
//! the dev keys directory, created by `just dev-keys`. `relational-tee
//! dev-token` mints Entra-shaped tokens with it, valid or deliberately bad,
//! so tests, the fault-injection suite and CI can call the API offline.
//! Release builds contain none of this.

use std::path::Path;

use super::entra::mint::Spec;
use crate::config::EntraConfig;
use crate::tee::dev_rsa::RsaSigner;

/// The user `dev-token` names unless told otherwise, so repeated tokens
/// are the same user.
pub const DEFAULT_OID: &str = "d0000000-0000-4000-8000-000000000001";

const USAGE: &str = "usage: relational-tee dev-token [--roles R1,R2] [--groups G1,G2] [--oid ID] \
    [--tid ID] [--email E] [--name N] [--azp ID] \
    [--bad expired|not-yet-valid|audience|tenant|client|scope]

Prints a token signed with the dev token signing key, for the Entra settings
in the environment (the dev app registrations by default). --roles defaults to
Admin; pass --roles '' for none. --groups sets the groups claim, which the
employer-scope mapping turns into the rows an analyst sees. --bad makes a
token the worker must refuse.";

fn list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(String::from)
        .collect()
}

/// Create the dev token signing key in `dir` if it's missing.
pub fn generate_missing(dir: &Path) -> std::io::Result<Option<std::path::PathBuf>> {
    let path = dir.join(crate::config::DEV_TOKEN_KEY_FILE);
    Ok(crate::tee::dev_rsa::generate_missing(&path)?.then_some(path))
}

/// The token `args` describe (the arguments after `dev-token`).
pub fn spec_from_args(config: &EntraConfig, args: &[String]) -> Result<Spec, String> {
    let mut spec = Spec::valid(config);
    spec.oid = DEFAULT_OID.into();
    spec.roles = vec!["Admin".into()];
    spec.name = Some("Dev User".into());
    spec.email = Some("dev@relational.invalid".into());
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let mut value = || {
            args.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value\n\n{USAGE}"))
        };
        match flag.as_str() {
            "--roles" => spec.roles = list(&value()?),
            "--groups" => spec.groups = list(&value()?),
            "--oid" => spec.oid = value()?,
            "--tid" => spec.tid = value()?,
            "--email" => spec.email = Some(value()?),
            "--name" => spec.name = Some(value()?),
            "--azp" => spec.azp = value()?,
            "--bad" => match value()?.as_str() {
                "expired" => spec.expires_in = -3600,
                "not-yet-valid" => spec.not_before_in = 3600,
                "audience" => spec.aud = format!("api://{}", config.api_client_id),
                "tenant" => spec.tid = uuid::Uuid::new_v4().to_string(),
                "client" => spec.azp = uuid::Uuid::new_v4().to_string(),
                "scope" => spec.scp = None,
                other => return Err(format!("unknown --bad {other:?}\n\n{USAGE}")),
            },
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument {other:?}\n\n{USAGE}")),
        }
    }
    Ok(spec)
}

/// Run `relational-tee dev-token`: print a token. Returns the exit code.
pub fn run(args: &[String]) -> i32 {
    let lookup = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
    let config = match crate::config::entra_from_lookup(&lookup) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let spec = match spec_from_args(&config, args) {
        Ok(spec) => spec,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let key_path = crate::config::dev_token_key_from_lookup(&lookup);
    match RsaSigner::load(&key_path).and_then(|signer| spec.sign(&signer)) {
        Ok(token) => {
            println!("{token}");
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::entra::tests::config;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_shape_the_token() {
        let spec = spec_from_args(&config(), &[]).unwrap();
        assert_eq!(spec.roles, ["Admin"]);
        assert_eq!(spec.oid, DEFAULT_OID);

        let spec = spec_from_args(
            &config(),
            &args(&["--roles", "", "--oid", "o-1", "--bad", "scope"]),
        )
        .unwrap();
        assert!(spec.roles.is_empty());
        assert_eq!(spec.oid, "o-1");
        assert!(spec.scp.is_none());

        let spec = spec_from_args(
            &config(),
            &args(&["--roles", "Analyst", "--groups", "g-aib, g-ebs,"]),
        )
        .unwrap();
        assert_eq!(spec.roles, ["Analyst"]);
        assert_eq!(spec.groups, ["g-aib", "g-ebs"]);

        let spec = spec_from_args(&config(), &args(&["--bad", "audience"])).unwrap();
        assert_eq!(spec.aud, "api://aa827d93-d487-40bf-8956-b6872ed55290");
        assert!(spec_from_args(&config(), &args(&["--bad", "nope"])).is_err());
        assert!(spec_from_args(&config(), &args(&["--oid"])).is_err());
    }
}
