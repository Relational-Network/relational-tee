// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The storage contract, checked against every backend: the in-memory
//! store always, and Azurite with `just test-azurite`.

use bytes::Bytes;

use super::store::{
    Container, Entity, Filter, IndexStore, InsertOutcome, ObjectStore, Prop, PutOutcome, RkRange,
    StoreError, Table,
};

/// Run every check. `run` keeps keys unique, so reruns against a shared
/// store don't collide.
pub(crate) async fn check_all(objects: &dyn ObjectStore, index: &dyn IndexStore) {
    let run = uuid::Uuid::new_v4().simple().to_string();
    create_only_writes(objects, &run).await;
    append_blobs(objects, &run).await;
    conditional_row_writes(index, &run).await;
    queries_and_pages(index, &run).await;
}

async fn create_only_writes(objects: &dyn ObjectStore, run: &str) {
    let path = format!("conformance/{run}/object.bin");
    assert!(objects
        .get(Container::Datasets, &path)
        .await
        .unwrap()
        .is_none());
    let first = objects
        .put_if_absent(Container::Datasets, &path, Bytes::from_static(b"first"))
        .await
        .unwrap();
    assert!(matches!(first, PutOutcome::Created(_)));
    let second = objects
        .put_if_absent(Container::Datasets, &path, Bytes::from_static(b"second"))
        .await
        .unwrap();
    assert_eq!(
        second,
        PutOutcome::AlreadyExists,
        "a second create-only write is refused"
    );
    let got = objects
        .get(Container::Datasets, &path)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.body.as_ref(), b"first");
}

async fn append_blobs(objects: &dyn ObjectStore, run: &str) {
    let path = format!("conformance/{run}/log.jsonl");
    for line in ["one\n", "two\n"] {
        objects
            .append(Container::Audit, &path, Bytes::from(line))
            .await
            .unwrap();
    }
    let got = objects.get(Container::Audit, &path).await.unwrap().unwrap();
    assert_eq!(got.body.as_ref(), b"one\ntwo\n");
}

fn row(pk: &str, rk: &str, state: &str) -> Entity {
    Entity::new(pk, rk)
        .with("state", Prop::Str(state.into()))
        .with("payload", Prop::Bin(vec![0, 1, 2, 3, 255]))
}

async fn conditional_row_writes(index: &dyn IndexStore, run: &str) {
    let pk = format!("cas-{run}");
    let InsertOutcome::Inserted(v1) = index
        .insert(Table::Pools, row(&pk, "a", "one"))
        .await
        .unwrap()
    else {
        panic!("first insert succeeds");
    };
    assert_eq!(
        index
            .insert(Table::Pools, row(&pk, "a", "again"))
            .await
            .unwrap(),
        InsertOutcome::Conflict
    );

    let read = index.get(Table::Pools, &pk, "a").await.unwrap().unwrap();
    assert_eq!(read.str("state"), Some("one"));
    assert_eq!(read.bin("payload"), Some(&[0, 1, 2, 3, 255][..]));
    assert_eq!(read.etag.as_ref(), Some(&v1));

    let v2 = index
        .update_if_match(Table::Pools, row(&pk, "a", "two"), &v1)
        .await
        .unwrap();
    assert_ne!(v1, v2);
    assert!(
        matches!(
            index
                .update_if_match(Table::Pools, row(&pk, "a", "stale"), &v1)
                .await,
            Err(StoreError::PreconditionFailed)
        ),
        "a write with a stale ETag fails"
    );
    assert!(matches!(
        index
            .update_if_match(Table::Pools, row(&pk, "missing", "x"), &v2)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        index.delete_if_match(Table::Pools, &pk, "a", &v1).await,
        Err(StoreError::PreconditionFailed)
    ));

    let v3 = index
        .upsert(Table::Pools, row(&pk, "a", "three"))
        .await
        .unwrap();
    index
        .delete_if_match(Table::Pools, &pk, "a", &v3)
        .await
        .unwrap();
    assert!(index.get(Table::Pools, &pk, "a").await.unwrap().is_none());
    index
        .upsert(Table::Pools, row(&pk, "b", "fresh"))
        .await
        .unwrap();
    assert!(index.get(Table::Pools, &pk, "b").await.unwrap().is_some());
}

async fn queries_and_pages(index: &dyn IndexStore, run: &str) {
    let pk = format!("query-{run}");
    for (rk, state, ok) in [
        ("log:1", "ready", true),
        ("log:2", "needs_init", true),
        ("log:3", "ready", false),
        ("log:4", "ready", true),
        ("rec:1", "ready", true),
    ] {
        let entity = row(&pk, rk, state).with("success", Prop::Bool(ok));
        index.insert(Table::Records, entity).await.unwrap();
    }
    // Another partition never leaks in.
    index
        .insert(Table::Records, row(&format!("{pk}x"), "log:0", "ready"))
        .await
        .unwrap();

    let logs = RkRange::between(Some("log:".into()), Some("log;".into()));
    let mut seen = Vec::new();
    let mut page = None;
    loop {
        let got = index
            .query(Table::Records, &pk, logs.clone(), None, 2, page)
            .await
            .unwrap();
        assert!(got.items.len() <= 2);
        seen.extend(got.items.into_iter().map(|e| e.rk));
        match got.next {
            Some(next) => page = Some(next),
            None => break,
        }
    }
    assert_eq!(seen, ["log:1", "log:2", "log:3", "log:4"]);

    let ready_and_ok = Filter::And(vec![
        Filter::eq("state", Prop::Str("ready".into())),
        Filter::eq("success", Prop::Bool(true)),
    ]);
    let got = index
        .query(
            Table::Records,
            &pk,
            logs.clone(),
            Some(ready_and_ok),
            100,
            None,
        )
        .await
        .unwrap();
    let rks: Vec<_> = got.items.iter().map(|e| e.rk.as_str()).collect();
    assert_eq!(rks, ["log:1", "log:4"]);

    let either = Filter::Or(vec![
        Filter::eq("state", Prop::Str("needs_init".into())),
        Filter::eq("success", Prop::Bool(false)),
    ]);
    let got = index
        .query(Table::Records, &pk, RkRange::all(), Some(either), 100, None)
        .await
        .unwrap();
    let rks: Vec<_> = got.items.iter().map(|e| e.rk.as_str()).collect();
    assert_eq!(rks, ["log:2", "log:3"]);
    assert!(
        got.items.iter().all(|e| e.etag.is_some()),
        "query rows carry ETags"
    );
}

#[tokio::test]
async fn memory_store_meets_the_contract() {
    let store = super::memory::MemoryStore::new();
    check_all(&store, &store).await;
}

/// Against Azurite on its default ports: `just test-azurite` starts it and
/// runs the ignored tests.
#[cfg(feature = "dev")]
#[tokio::test]
#[ignore = "needs Azurite: run `just test-azurite`"]
async fn azurite_meets_the_contract() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let store = super::azure::AzureStore::new(&super::azure::AzureConfig {
        blob_url: crate::config::AZURITE_BLOB_URL.into(),
        table_url: crate::config::AZURITE_TABLE_URL.into(),
        credential: super::azure::CredentialConfig::AzuriteDevAccount,
    })
    .expect("Azurite config");
    store.ensure_layout().await.expect("Azurite reachable");
    check_all(&store, &store).await;
}
