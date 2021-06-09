// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::{collections::BTreeSet, convert::TryFrom as _, thread};

use librad::{
    git::{
        storage::watch::{EventKind, NamespaceEvent, ReflogEvent, DEBOUNCE_DELAY},
        Urn,
    },
    git_ext::RefLike,
    keys::SecretKey,
    reflike,
};

use crate::{librad::git::storage::storage, logging, rad::identities::TestProject};

#[test]
fn namespaces() {
    logging::init();

    let store = storage(SecretKey::new());
    let (watcher, events) = store.watch().namespaces().unwrap();
    let TestProject { project, owner } = TestProject::create(&store).unwrap();

    thread::sleep(DEBOUNCE_DELAY);
    drop(watcher);

    let events = events
        .map(|NamespaceEvent { path, kind }| {
            (
                Urn::try_from(RefLike::try_from(path.to_str().unwrap()).unwrap()).unwrap(),
                kind,
            )
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        vec![
            (project.urn(), EventKind::Create),
            (owner.urn(), EventKind::Create)
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        events
    )
}

#[test]
fn reflogs() {
    logging::init();

    let store = storage(SecretKey::new());
    let (watcher, events) = store.watch().reflogs().unwrap();
    let TestProject { project, owner } = TestProject::create(&store).unwrap();

    thread::sleep(DEBOUNCE_DELAY);
    drop(watcher);

    let events = events
        .map(|ReflogEvent { path, kind }| {
            (
                Urn::try_from(RefLike::try_from(path.to_str().unwrap()).unwrap()).unwrap(),
                kind,
            )
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        vec![
            (
                project.urn().with_path(reflike!("refs/rad/id")),
                EventKind::Create
            ),
            (
                project.urn().with_path(reflike!("refs/rad/self")),
                EventKind::Create
            ),
            (
                project
                    .urn()
                    .with_path(reflike!("refs/rad/ids").join(owner.urn())),
                EventKind::Create
            ),
            (
                owner.urn().with_path(reflike!("refs/rad/id")),
                EventKind::Create
            ),
            (
                owner.urn().with_path(reflike!("refs/rad/self")),
                EventKind::Create
            )
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        events
    )
}