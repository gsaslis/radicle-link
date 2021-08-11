// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::{
    borrow::Cow,
    collections::{BTreeSet, HashSet},
};

use bstr::ByteSlice as _;
use link_crypto::PeerId;
use link_git_protocol::Ref;

use super::{guard_required, mk_ref_update, ref_prefixes, required_refs, DelegateIds};
use crate::{
    error,
    refs,
    FilteredRef,
    Identities,
    Layout,
    Negotiation,
    Refdb,
    Update,
    UpdateTips,
    WantsHaves,
};

#[derive(Debug)]
pub struct ForFetch {
    /// The local peer, so we don't fetch our own data.
    pub local_id: PeerId,
    /// The remote peer being fetched from.
    pub remote_id: PeerId,
    /// The set of keys the latest known identity revision delegates to.
    /// Indirect delegations are resolved.
    pub delegates: BTreeSet<PeerId>,
    /// Additional peers being tracked (ie. excluding `delegates`).
    pub tracked: BTreeSet<PeerId>,
}

impl ForFetch {
    pub fn peers(&self) -> impl Iterator<Item = &PeerId> {
        self.delegates
            .iter()
            .chain(self.tracked.iter())
            .filter(move |id| *id != &self.local_id)
    }

    pub fn required_refs(&self) -> impl Iterator<Item = refs::Scoped<'_, 'static>> {
        self.delegates
            .iter()
            .filter(move |id| *id != &self.local_id)
            .flat_map(move |id| required_refs(id, &self.remote_id))
    }
}

impl Negotiation for ForFetch {
    fn ref_prefixes(&self) -> Vec<refs::Scoped<'_, 'static>> {
        self.peers()
            .flat_map(move |id| ref_prefixes(id, &self.remote_id))
            .collect()
    }

    fn ref_filter<'a>(&'a self, r: &'a Ref) -> Option<FilteredRef<'a, Self>> {
        use refs::parsed::Identity;

        let refname = r.unpack().0;
        let refs::Parsed { remote, inner } = refs::parse::<Identity>(refname.as_bstr())?;

        if let Some(remote_id) = remote {
            if remote_id == self.local_id {
                return None;
            }
        }

        inner.left().map(|_| {
            FilteredRef::new(
                remote
                    .map(Cow::Owned)
                    .unwrap_or(Cow::Borrowed(&self.remote_id)),
                r,
            )
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

        let peers: BTreeSet<&PeerId> = self.peers().collect();
        for r in refs {
            let (name, oid) = r.inner.unpack();

            let refname = refs::remote_tracking(&r.remote_id, name.as_bstr());
            if let Some(oid) = db.refname_to_id(&refname)? {
                haves.insert(oid.into());
            }

            if peers.contains(r.remote_id.as_ref()) {
                wants.insert(*oid);
                wanted.insert(r);
            }
        }

        Ok(WantsHaves {
            wanted,
            wants,
            haves,
        })
    }
}

impl UpdateTips for ForFetch {
    fn prepare<'a, I>(
        &self,
        ids: &I,
        refs: &'a [FilteredRef<'a, Self>],
    ) -> Result<Vec<Vec<Update<'a>>>, error::Prepare<I::VerificationError>>
    where
        I: Identities,
        I::Urn: Ord,
    {
        let delegate_ids = refs.iter().collect::<DelegateIds<I::Urn>>();
        // == Transaction groups
        //
        // Group into delegate and non-delegate refs, so we can keep the number
        // of refs to lock lower. We want all delegates to be updated atomically,
        // though, as otherwise it becomes difficult to reason about the
        // correctness of subsequent steps. Other refs _could_ be split up
        // further per remote peer, but we'll see if that is worthwhile.
        //
        // The delegate tx goes first, as we should abort if that fails.
        let mut delegate_updates = Vec::new();
        let mut other_updates = Vec::new();
        for r in refs {
            debug_assert!(
                r.remote_id.as_ref() != &self.local_id,
                "never touch our own"
            );
            let (name, oid) = r.inner.unpack();
            let is_delegate = self.delegates.contains(&r.remote_id);
            // XXX: we should verify all ids at some point, but non-delegates
            // would be a warning only
            if is_delegate && name.ends_with(b"rad/id") {
                Identities::verify(ids, oid, delegate_ids.for_remote(r.remote_id.as_ref()))
                    .map_err(error::Prepare::Verification)?;
            }
            if let Some(u) = mk_ref_update::<_, I::Urn>(r) {
                if is_delegate {
                    delegate_updates.push(u);
                } else {
                    other_updates.push(u)
                }
            }
        }

        Ok(vec![delegate_updates, other_updates])
    }
}

impl Layout for ForFetch {
    fn pre_validate<'a>(&self, refs: &'a [FilteredRef<'a, Self>]) -> Result<(), error::Layout> {
        guard_required(
            self.required_refs().collect(),
            refs.iter().map(|x| x.as_scoped(&self.remote_id)).collect(),
        )
    }
}
