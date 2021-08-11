// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap, HashSet},
};

use bstr::{BStr, BString, ByteSlice as _};
use itertools::Itertools;
use link_crypto::PeerId;
use link_git_protocol::{oid, Ref};

use crate::{
    error,
    refs,
    sigrefs,
    FilteredRef,
    Identities,
    Layout,
    Negotiation,
    Policy,
    Refdb,
    Update,
    UpdateTips,
    WantsHaves,
};

#[derive(Debug)]
pub struct Fetch<Oid> {
    /// The local id.
    pub local_id: PeerId,
    /// The peer being fetched from.
    pub remote_id: PeerId,
    /// The stack of signed refs describing which refs we'll ask for.
    pub signed_refs: sigrefs::Combined<Oid>,
}

impl<T> Fetch<T> {
    fn scoped<'a, 'b: 'a>(
        &self,
        id: &'a PeerId,
        name: impl Into<Cow<'b, BStr>>,
    ) -> refs::Scoped<'a, 'b> {
        refs::scoped(id, &self.remote_id, name)
    }

    fn signed(&self, id: &PeerId, refname: impl AsRef<BStr>) -> Option<&T> {
        self.signed_refs
            .refs
            .get(id)
            .and_then(|refs| refs.refs.get(refname.as_ref()))
    }

    fn is_signed(&self, id: &PeerId, refname: impl AsRef<BStr>) -> bool {
        self.signed(id, refname).is_some()
    }

    fn is_tracked(&self, id: &PeerId) -> bool {
        self.signed_refs.remotes.contains(id)
    }
}

impl<T: AsRef<oid>> Negotiation for Fetch<T> {
    fn ref_prefixes(&self) -> Vec<refs::Scoped<'_, '_>> {
        let remotes = self
            .signed_refs
            .remotes
            .iter()
            .filter(move |id| *id != &self.local_id)
            .flat_map(move |id| {
                vec![
                    self.scoped(id, refs::Prefix::Heads),
                    self.scoped(id, refs::Prefix::Notes),
                    self.scoped(id, refs::Prefix::Tags),
                ]
            });
        let signed = self
            .signed_refs
            .refs
            .iter()
            .filter(move |(id, _)| *id != &self.local_id)
            .flat_map(move |(id, refs)| {
                refs.refs
                    .iter()
                    .map(move |(name, _)| self.scoped(id, name.as_bstr()))
            });

        remotes.chain(signed).collect()
    }

    fn ref_filter<'a>(&'a self, r: &'a Ref) -> Option<FilteredRef<'a, Self>> {
        use refs::parsed::{Cat, Identity, Refs};

        let refname = r.unpack().0;
        let refs::Parsed { remote, inner } = refs::parse::<Identity>(refname.as_bstr())?;
        let remote_id = remote
            .map(Cow::Owned)
            .unwrap_or(Cow::Borrowed(&self.remote_id));

        inner.right().and_then(|Refs { cat, name, .. }| match cat {
            // Only known "standard" refs.
            //
            // Peeking should've already gotten us the "rad" refs, and by
            // ignoring them here we don't have to worry about the remote
            // end becoming inconsistent between peek and fetch.
            //
            // XXX: allow to configure fetching "strange" refs
            Cat::Unknown(_) => {
                warn!("skipping unknown cat {}", cat);
                None
            },
            Cat::Heads | Cat::Notes | Cat::Tags => {
                let refname_no_remote: BString = Itertools::intersperse(
                    vec![refs::component::REFS, cat.as_bytes()]
                        .into_iter()
                        .chain(name),
                    &[refs::SEPARATOR],
                )
                .collect();
                if self.is_tracked(&remote_id) || self.is_signed(&remote_id, &refname_no_remote) {
                    Some(FilteredRef::new(remote_id, r))
                } else {
                    warn!(
                        %refname_no_remote,
                        "skipping {:?}, as it is neither signed nor tracked", r
                    );
                    None
                }
            },
        })
    }

    fn wants_haves<'a, R: Refdb>(
        &self,
        db: &R,
        refs: impl IntoIterator<Item = FilteredRef<'a, Self>>,
    ) -> Result<WantsHaves<'a, Self>, R::FindError> {
        let mut wanted = HashSet::new();
        let mut wants = BTreeSet::new();
        let mut haves = BTreeSet::new();

        for r in refs {
            let (name, tip) = r.inner.unpack();

            let refname = refs::remote_tracking(&r.remote_id, name.as_bstr());
            let refname_no_remote = refs::owned(name.as_bstr());

            let have = db.refname_to_id(&refname)?;
            if let Some(oid) = have.as_ref() {
                haves.insert(oid.as_ref().to_owned());
            }

            // If we have a signed ref, we `want` the signed oid. Otherwise, and
            // if the remote id is in the tracking graph, we `want` what we got
            // offered.
            let want: Option<&oid> = self
                .signed(&r.remote_id, &refname_no_remote)
                .map(|s| s.as_ref())
                .or_else(|| self.is_tracked(&r.remote_id).then_some(tip.as_ref()));

            match (want, have) {
                (Some(want), Some(have)) if want == have.as_ref() => {
                    // No need to want what we already have
                },
                (None, _) => {
                    // Unsolicited
                },
                (Some(_want), _) => {
                    wants.insert(*tip);
                    wanted.insert(r);
                },
            }
        }

        Ok(WantsHaves {
            wanted,
            wants,
            haves,
        })
    }
}

impl<T: AsRef<oid>> UpdateTips for Fetch<T> {
    fn prepare<'a, I: Identities>(
        &self,
        _: &I,
        refs: &'a [FilteredRef<'a, Self>],
    ) -> Result<Vec<Vec<Update<'a>>>, error::Prepare<I::VerificationError>> {
        // == Transaction groups
        //
        // Group by remote id, yielding transactions in random order to reduce
        // contention.
        let mut grouped = refs.iter().fold(HashMap::new(), |mut acc, r| {
            debug_assert!(
                r.remote_id.as_ref() != &self.local_id,
                "never touch our own"
            );
            let (name, oid) = r.inner.unpack();
            let refname = refs::remote_tracking(&r.remote_id, name.as_bstr());
            let up = Update::Direct {
                name: Cow::from(refname),
                target: *oid,
                no_ff: Policy::Allow,
            };

            acc.entry(&r.remote_id).or_insert_with(Vec::new).push(up);
            acc
        });

        // Include a no-op update of the corresponding sigrefs to ensure
        // consistency in case the same URN is fetched concurrently.
        for (peer, updates) in grouped.iter_mut() {
            match self.signed_refs.refs.get(peer) {
                Some(refs) => updates.push(Update::Noop {
                    name: refs::remote_tracking(peer, Cow::from(refs::Signed)).into(),
                    expect: refs.at.as_ref().to_owned(),
                }),

                None if self.signed_refs.remotes.contains(peer) => continue,
                None => unreachable!("peer {} is neither tracked nor has signed refs", peer),
            }
        }

        Ok(grouped.into_values().collect())
    }
}

impl<T> Layout for Fetch<T> {
    // [`Fetch`] may request only a part of the refs tree, so no layout error
    // can be determined from the advertised refs alone.
    //
    // XXX: We could reject if only a subset of the signed refs are present. This
    // would interact with fetchspecs, so requires runtime configuration.
    fn pre_validate<'a>(&self, _: &'a [FilteredRef<'a, Self>]) -> Result<(), error::Layout> {
        Ok(())
    }
}
