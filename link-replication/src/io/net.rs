// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::{borrow::Cow, io, marker::PhantomData, path::PathBuf};

use bstr::BString;
use futures_lite::io::{AsyncRead, AsyncWrite};
use link_git_protocol as git;

use crate::{FilteredRef, Negotiation, Net, Odb, Refdb, Urn, WantsHaves};

#[async_trait]
pub trait Connection {
    type Read: AsyncRead + Unpin;
    type Write: AsyncWrite + Unpin;
    type Error: std::error::Error + Send + Sync + 'static;

    async fn open_stream(&self) -> Result<(Self::Read, Self::Write), Self::Error>;
}

pub struct Network<U, D, B, C> {
    git_dir: PathBuf,
    urn: U,
    db: D,
    conn: C,
    _marker: PhantomData<B>,
}

impl<U, D, B, C> Network<U, D, B, C> {
    pub fn new(db: D, conn: C, git_dir: impl Into<PathBuf>, urn: U) -> Self {
        Self {
            git_dir: git_dir.into(),
            db,
            conn,
            urn,
            _marker: PhantomData,
        }
    }
}

#[async_trait(?Send)]
impl<U, D, B, C> Net for Network<U, D, B, C>
where
    U: Urn,

    D: Refdb + Odb + AsRef<B>,
    D::FindError: Send + Sync,

    B: ToOwned,
    <B as ToOwned>::Owned: git::packwriter::BuildThickener + Send + 'static,

    C: Connection,
    C::Read: Send + 'static,
    C::Write: Send + 'static,
    C::Error: Send + Sync,
{
    type Error = io::Error;

    #[tracing::instrument(level = "debug", skip(self, neg), err)]
    async fn run_fetch<N, T>(&self, neg: N) -> Result<(N, Vec<FilteredRef<'static, T>>), io::Error>
    where
        N: Negotiation<T> + Send,
        T: Send + 'static,
    {
        let git_dir = self.git_dir.clone();
        let repo = BString::from(self.urn.encode_id());

        let refs = {
            let mut ref_prefixes = neg
                .ref_prefixes()
                .into_iter()
                .map(|s| Cow::from(s).into_owned())
                .collect::<Vec<_>>();
            ref_prefixes.sort();
            ref_prefixes.dedup();

            let (recv, send) = self
                .conn
                .open_stream()
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            git::ls_refs(
                git::ls::Options {
                    repo: repo.clone(),
                    extra_params: vec![],
                    ref_prefixes,
                },
                recv,
                send,
            )
            .await?
        };

        let WantsHaves {
            wanted,
            mut wants,
            haves,
        } = neg
            .wants_haves(
                &self.db,
                refs.iter()
                    .filter_map(|r| neg.ref_filter(r).map(|f| f.into_owned())),
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        wants.retain(|oid| !haves.contains(oid));
        if wants.is_empty() {
            info!("want nothing");
            return Ok((neg, vec![]));
        }
        let wants: Vec<_> = wants.into_iter().collect();
        let haves: Vec<_> = haves.into_iter().collect();

        let out = {
            let thick: B::Owned = self.db.as_ref().to_owned();
            let (recv, send) = self
                .conn
                .open_stream()
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            git::fetch(
                git::fetch::Options {
                    repo,
                    extra_params: vec![],
                    wants,
                    haves,
                    want_refs: vec![],
                },
                {
                    let git_dir = git_dir.clone();
                    move |stop| {
                        git::packwriter::Standard::new(
                            git_dir,
                            git::packwriter::Options::default(),
                            thick,
                            stop,
                        )
                    }
                },
                recv,
                send,
            )
            .await?
        };
        self.db
            .add_pack(
                out.pack
                    .expect("packfile must have been written")
                    .index_path
                    .expect("written packfile must have a path"),
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let refs_in_pack = out
            .wanted_refs
            .into_iter()
            .filter_map(|r| neg.ref_filter(&r).map(|f| f.into_owned()))
            .chain(wanted)
            .collect::<Vec<_>>();

        // Validate we got all requested tips in the pack
        for r in &refs_in_pack {
            let (name, oid) = r.inner.unpack();
            if !self.db.contains(oid) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("advertised ref {} {} not found in pack", name, oid),
                ));
            }
        }

        Ok((neg, refs_in_pack))
    }
}
