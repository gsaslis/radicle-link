// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::{sync::Arc, time::Duration};

use async_lock::Semaphore;

use crate::{
    executor,
    git::{
        identities::local::LocalIdentity,
        storage::{read::ReadOnlyStorage as _, Storage},
    },
    identities::git::Urn,
    net::{connection::RemotePeer as _, quic},
    PeerId,
};

pub use link_replication::{Error, ErrorBox};

mod context;
use context::Context;

pub type Success = link_replication::Success<context::Urn>;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub limit: FetchLimit,
    pub slots: usize,
    pub wait_slot: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            limit: FetchLimit::default(),
            slots: 4,
            wait_slot: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FetchLimit {
    pub peek: usize,
    pub data: usize,
}

impl Default for FetchLimit {
    fn default() -> Self {
        Self {
            peek: 1024 * 1024 * 5,
            data: 1024 * 1024 * 1024 * 5,
        }
    }
}

#[derive(Clone)]
pub struct Replication {
    slots: Arc<Semaphore>,
}

impl Replication {
    pub fn new(config: Config) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(config.slots)),
        }
    }

    pub async fn replicate<S>(
        &self,
        spawner: &executor::Spawner,
        store: S,
        conn: quic::Connection,
        urn: Urn,
        whoami: Option<LocalIdentity>,
    ) -> Result<Success, Error>
    where
        S: AsRef<Storage> + Send + 'static,
    {
        // TODO: timeout
        let slot = self.slots.acquire_arc().await;
        let res = spawner
            .blocking(move || {
                let store = store.as_ref();
                let have_urn = store.has_urn(&urn)?;
                let remote_id = conn.remote_peer_id();

                let mut cx = Context::new(store, conn, context::Urn::from(urn))?;
                let whoami = whoami.map(|id| link_replication::LocalIdentity {
                    tip: id.content_id.into(),
                    ids: id
                        .delegations()
                        .into_iter()
                        .copied()
                        .map(PeerId::from)
                        .collect(),
                });

                if have_urn {
                    link_replication::pull(&mut cx, remote_id, whoami)
                } else {
                    link_replication::clone(&mut cx, remote_id, whoami)
                }
            })
            .await;
        drop(slot);
        res
    }
}
