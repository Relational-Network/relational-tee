// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The store contract, checked against every backend: local files always,
//! and Azurite with `just test-azurite`.

use bytes::Bytes;

use super::{Created, ETag, Fetched, ObjectStore, Replaced, StoreError};

/// Run every check. `run` keeps names unique, so reruns against a shared
/// store don't collide.
pub(crate) async fn check_all(store: &dyn ObjectStore) {
    let run = format!("conformance/{}", uuid::Uuid::new_v4().simple());
    create_only_writes(store, &run).await;
    conditional_reads(store, &run).await;
    compare_and_swap(store, &run).await;
    lists(store, &run).await;
    names(store).await;
}

async fn found(store: &dyn ObjectStore, path: &str) -> (Bytes, ETag) {
    match store.get(path, None).await.unwrap() {
        Fetched::Found { body, etag } => (body, etag),
        other => panic!("{path}: expected an object, got {other:?}"),
    }
}

async fn create_only_writes(store: &dyn ObjectStore, run: &str) {
    let path = format!("{run}/object.bin");
    assert_eq!(store.get(&path, None).await.unwrap(), Fetched::Missing);
    let first = store
        .put_if_absent(&path, Bytes::from_static(b"first"))
        .await
        .unwrap();
    let Created::New(etag) = first else {
        panic!("the first create-only write lands");
    };
    assert_eq!(
        store
            .put_if_absent(&path, Bytes::from_static(b"second"))
            .await
            .unwrap(),
        Created::AlreadyExists,
        "a second create-only write is refused"
    );
    let (body, current) = found(store, &path).await;
    assert_eq!(body.as_ref(), b"first");
    assert_eq!(current, etag);
}

async fn conditional_reads(store: &dyn ObjectStore, run: &str) {
    let path = format!("{run}/cached.bin");
    store
        .put_if_absent(&path, Bytes::from_static(b"cached"))
        .await
        .unwrap();
    let (_, etag) = found(store, &path).await;
    assert_eq!(
        store.get(&path, Some(&etag)).await.unwrap(),
        Fetched::NotModified,
        "a read with the current ETag costs no body"
    );
    let stale = ETag::from_raw("0x0");
    assert!(matches!(
        store.get(&path, Some(&stale)).await.unwrap(),
        Fetched::Found { .. }
    ));
}

async fn compare_and_swap(store: &dyn ObjectStore, run: &str) {
    let path = format!("{run}/cas.bin");
    let Created::New(v1) = store
        .put_if_absent(&path, Bytes::from_static(b"one"))
        .await
        .unwrap()
    else {
        panic!("created");
    };
    let Replaced::Done(v2) = store
        .put_if_match(&path, Bytes::from_static(b"two"), &v1)
        .await
        .unwrap()
    else {
        panic!("the current ETag wins");
    };
    assert_ne!(v1, v2);
    assert_eq!(
        store
            .put_if_match(&path, Bytes::from_static(b"stale"), &v1)
            .await
            .unwrap(),
        Replaced::Stale,
        "a write with a stale ETag fails"
    );
    assert_eq!(found(store, &path).await.0.as_ref(), b"two");
    assert_eq!(
        store
            .put_if_match(&format!("{run}/missing.bin"), Bytes::new(), &v2)
            .await
            .unwrap(),
        Replaced::Stale
    );
}

async fn lists(store: &dyn ObjectStore, run: &str) {
    let dir = format!("{run}/list/");
    for name in ["b.json", "a.json", "a/nested.json"] {
        store
            .put_if_absent(&format!("{dir}{name}"), Bytes::from(name))
            .await
            .unwrap();
    }
    let listed = store.list(&dir).await.unwrap();
    let paths: Vec<_> = listed.iter().map(|l| l.path.clone()).collect();
    assert_eq!(
        paths,
        [format!("{dir}a.json"), format!("{dir}b.json")],
        "only the objects directly under the directory, in name order"
    );
    for entry in &listed {
        assert_eq!(found(store, &entry.path).await.1, entry.etag);
    }
    assert!(store
        .list(&format!("{run}/nothing/"))
        .await
        .unwrap()
        .is_empty());
}

async fn names(store: &dyn ObjectStore) {
    assert!(matches!(
        store.get("pools/../wallets/x.json", None).await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.list("pools").await,
        Err(StoreError::Invalid(_))
    ));
}

#[tokio::test]
async fn local_files_meet_the_contract() {
    check_all(&super::files::LocalFiles::temporary()).await;
}

/// Against Azurite on its default port: `just test-azurite` starts it and
/// runs the ignored tests.
#[cfg(feature = "dev")]
#[tokio::test]
#[ignore = "needs Azurite: run `just test-azurite`"]
async fn azurite_meets_the_contract() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let store = super::azure::AzureBlob::new(
        &super::azure::AzureConfig {
            blob_url: crate::config::AZURITE_BLOB_URL.into(),
            credential: super::azure::CredentialConfig::AzuriteDevAccount,
        },
        super::STATE,
    )
    .expect("Azurite config");
    store.ensure_container().await.expect("Azurite reachable");
    check_all(&store).await;
}
