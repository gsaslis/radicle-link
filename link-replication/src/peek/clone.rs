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
    ids,
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
pub struct ForClone {
    pub remote_id: PeerId,
}

impl ForClone {
    pub fn required_refs(&self) -> impl Iterator<Item = refs::Scoped<'_, 'static>> {
        required_refs(&self.remote_id, &self.remote_id)
    }
}

impl Negotiation for ForClone {
    fn ref_prefixes(&self) -> Vec<refs::Scoped<'_, 'static>> {
        ref_prefixes(&self.remote_id, &self.remote_id).collect()
    }

    fn ref_filter<'a>(&'a self, r: &'a Ref) -> Option<FilteredRef<'a, Self>> {
        use either::Either::Left;
        use refs::parsed::Identity;

        let refname = r.unpack().0;
        match refs::parse::<Identity>(refname.as_bstr())? {
            refs::Parsed {
                remote: None,
                inner: Left(_),
            } => Some(FilteredRef::new(Cow::Borrowed(&self.remote_id), r)),
            _ => None,
        }
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
            assert!(
                r.remote_id.as_ref() == &self.remote_id,
                "`ref_filter` should let through only non-remote-tracking branches"
            );

            let (name, oid) = r.inner.unpack();
            let refname = refs::remote_tracking(&r.remote_id, name.as_bstr());
            if let Some(oid) = db.refname_to_id(&refname)? {
                haves.insert(oid.into());
            }

            wants.insert(*oid);
            wanted.insert(r);
        }

        Ok(WantsHaves {
            wanted,
            wants,
            haves,
        })
    }
}

impl UpdateTips for ForClone {
    fn prepare<'a, I>(
        &self,
        ids: &I,
        refs: &'a [FilteredRef<'a, Self>],
    ) -> Result<Vec<Vec<Update<'a>>>, error::Prepare<I::VerificationError>>
    where
        I: Identities,
        I::Urn: Ord,
    {
        use ids::VerifiedIdentity as _;

        let id = refs
            .iter()
            .find(|r| {
                r.remote_id.as_ref() == &self.remote_id
                    && refs::RadId.as_bytes() == AsRef::<[u8]>::as_ref(r.inner.unpack().0)
            })
            .expect("`pre_validate` ensures we have a refs/rad/id");
        let oid = id.inner.unpack().1;
        let verified = Identities::verify(
            ids,
            oid,
            refs.iter()
                .collect::<DelegateIds<I::Urn>>()
                .for_remote(id.remote_id.as_ref()),
        )
        .map_err(error::Prepare::Verification)?;

        let updates = if verified.delegate_ids().contains(&self.remote_id) {
            vec![refs.iter().filter_map(mk_ref_update::<_, I::Urn>).collect()]
        } else {
            vec![]
        };

        Ok(updates)
    }
}

impl Layout for ForClone {
    fn pre_validate<'a>(&self, refs: &'a [FilteredRef<'a, Self>]) -> Result<(), error::Layout> {
        guard_required(
            self.required_refs().collect(),
            refs.iter().map(|x| x.as_scoped(&self.remote_id)).collect(),
        )
    }
}
