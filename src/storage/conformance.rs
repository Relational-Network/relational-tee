// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The storage contract, checked against every backend: the in-memory
//! store always, and Azurite with `just test-azurite`.

use bytes::Bytes;

use super::store::{
    BatchOp, Container, Entity, IndexStore, InsertOutcome, ObjectStore, Prop, PutOutcome, RkRange,
    StoreError, Table,
};

/// Run every check. `run` keeps keys unique, so reruns against a shared
/// store don't collide. Azurite has no immutability policies, so that check
/// is optional.
pub(crate) async fn check_all(
    objects: &dyn ObjectStore,
    index: &dyn IndexStore,
    immutability: bool,
) {
    let run = uuid::Uuid::new_v4().simple().to_string();
    create_only_writes(objects, &run).await;
    append_blobs(objects, &run).await;
    deletes(objects, &run, immutability).await;
    conditional_row_writes(index, &run).await;
    queries_and_pages(index, &run).await;
    atomic_batches(index, &run).await;
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
            .append(Container::Revocations, &path, Bytes::from(line))
            .await
            .unwrap();
    }
    let got = objects
        .get(Container::Revocations, &path)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.body.as_ref(), b"one\ntwo\n");
}

async fn deletes(objects: &dyn ObjectStore, run: &str, immutability: bool) {
    let path = format!("conformance/{run}/staged.bin");
    objects
        .put_if_absent(Container::Datasets, &path, Bytes::from_static(b"x"))
        .await
        .unwrap();
    objects.delete(Container::Datasets, &path).await.unwrap();
    assert!(objects
        .get(Container::Datasets, &path)
        .await
        .unwrap()
        .is_none());
    objects.delete(Container::Datasets, &path).await.unwrap();

    if immutability {
        let path = format!("conformance/{run}/committed.bin");
        objects
            .put_if_absent(Container::Datasets, &path, Bytes::from_static(b"y"))
            .await
            .unwrap();
        let until = chrono::Utc::now() + chrono::Duration::days(1);
        objects
            .set_immutability(Container::Datasets, &path, until)
            .await
            .unwrap();
        assert!(matches!(
            objects.delete(Container::Datasets, &path).await,
            Err(StoreError::Conflict)
        ));
        assert!(objects
            .get(Container::Datasets, &path)
            .await
            .unwrap()
            .is_some());
    }
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
    for rk in ["log:1", "log:2", "log:3", "log:4", "rec:1"] {
        index
            .insert(Table::Records, row(&pk, rk, "ready"))
            .await
            .unwrap();
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
            .query(Table::Records, &pk, logs.clone(), 2, page)
            .await
            .unwrap();
        assert!(got.items.len() <= 2);
        assert!(
            got.items.iter().all(|e| e.etag.is_some()),
            "query rows carry ETags"
        );
        seen.extend(got.items.into_iter().map(|e| e.rk));
        match got.next {
            Some(next) => page = Some(next),
            None => break,
        }
    }
    assert_eq!(seen, ["log:1", "log:2", "log:3", "log:4"]);
}

async fn atomic_batches(index: &dyn IndexStore, run: &str) {
    let pk = format!("batch-{run}");
    let InsertOutcome::Inserted(etag) = index
        .insert(Table::Records, row(&pk, "rec:1", "staged"))
        .await
        .unwrap()
    else {
        panic!("first insert succeeds");
    };
    index
        .insert(Table::Records, row(&pk, "log:taken", "committed"))
        .await
        .unwrap();

    // One conflicting operation, and nothing is applied.
    let conflicting = index
        .batch(
            Table::Records,
            &pk,
            vec![
                BatchOp::UpdateIfMatch(row(&pk, "rec:1", "committed"), etag.clone()),
                BatchOp::Insert(row(&pk, "log:taken", "committed")),
            ],
        )
        .await;
    assert!(
        matches!(conflicting, Err(StoreError::Conflict)),
        "{conflicting:?}"
    );
    let rec = index
        .get(Table::Records, &pk, "rec:1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rec.str("state"),
        Some("staged"),
        "a failed batch changes nothing"
    );

    let stale = index
        .batch(
            Table::Records,
            &pk,
            vec![
                BatchOp::Insert(row(&pk, "log:2", "committed")),
                BatchOp::UpdateIfMatch(
                    row(&pk, "rec:1", "committed"),
                    super::store::ETag("W/\"datetime'2000-01-01T00%3A00%3A00Z'\"".into()),
                ),
            ],
        )
        .await;
    assert!(
        matches!(stale, Err(StoreError::PreconditionFailed)),
        "{stale:?}"
    );
    assert!(index
        .get(Table::Records, &pk, "log:2")
        .await
        .unwrap()
        .is_none());

    index
        .batch(
            Table::Records,
            &pk,
            vec![
                BatchOp::UpdateIfMatch(row(&pk, "rec:1", "committed"), etag),
                BatchOp::Insert(row(&pk, "log:2", "committed")),
            ],
        )
        .await
        .unwrap();
    let rec = index
        .get(Table::Records, &pk, "rec:1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec.str("state"), Some("committed"));
    assert!(index
        .get(Table::Records, &pk, "log:2")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn memory_store_meets_the_contract() {
    let store = super::memory::MemoryStore::new();
    check_all(&store, &store, true).await;
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
    check_all(&store, &store, false).await;
}
