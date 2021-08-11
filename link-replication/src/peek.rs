// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    iter::FromIterator,
};

use bstr::{BString, ByteSlice as _};
use link_crypto::PeerId;
use link_git_protocol::ObjectId;

use crate::{error, ids, refdb, refs, FilteredRef, Update};

mod clone;
pub use clone::ForClone;

mod fetch;
pub use fetch::ForFetch;

fn ref_prefixes<'a>(
    id: &'a PeerId,
    remote_id: &PeerId,
) -> impl Iterator<Item = refs::Scoped<'a, 'static>> {
    vec![
        refs::scoped(id, remote_id, refs::RadId),
        refs::scoped(id, remote_id, refs::RadSelf),
        refs::scoped(id, remote_id, refs::Prefix::RadIds),
        refs::scoped(id, remote_id, refs::Signed),
    ]
    .into_iter()
}

fn required_refs<'a>(
    id: &'a PeerId,
    remote_id: &PeerId,
) -> impl Iterator<Item = refs::Scoped<'a, 'static>> {
    vec![
        refs::scoped(id, remote_id, refs::RadId),
        refs::scoped(id, remote_id, refs::Signed),
    ]
    .into_iter()
}

fn guard_required<'a, 'b, 'c>(
    required_refs: BTreeSet<refs::Scoped<'a, 'b>>,
    wanted_refs: BTreeSet<refs::Scoped<'a, 'c>>,
) -> Result<(), error::Layout> {
    // We wanted nothing, so we can't expect anything
    if wanted_refs.is_empty() {
        return Ok(());
    }

    let diff = required_refs
        .difference(&wanted_refs)
        .map(|scoped| scoped.as_ref().to_owned())
        .collect::<Vec<_>>();

    if !diff.is_empty() {
        Err(error::Layout::MissingRequiredRefs(diff))
    } else {
        Ok(())
    }
}

fn mk_ref_update<'a, T, Urn>(fref: &'a FilteredRef<'a, T>) -> Option<Update<'a>>
where
    Urn: ids::Urn,
{
    use refdb::{Policy, SymrefTarget};
    use refs::parsed::Rad;

    let (name, oid) = fref.inner.unpack();
    let refs::Parsed { inner, .. } = refs::parse::<Urn>(name.as_bstr())?;
    let track_as = Cow::from(refs::remote_tracking(&fref.remote_id, name.as_bstr()));

    inner.left().map(|rad| match rad {
        Rad::Id | Rad::Me | Rad::SignedRefs => Update::Direct {
            name: track_as,
            target: *oid,
            no_ff: Policy::Abort,
        },

        Rad::Ids { urn } => Update::Symbolic {
            name: track_as,
            target: SymrefTarget {
                name: refs::Namespaced {
                    namespace: Some(BString::from(urn.encode_id()).into()),
                    refname: refs::RadId.into(),
                },
                target: *oid,
            },
            type_change: Policy::Allow,
        },
    })
}

pub(crate) struct DelegateIds<'a, Urn>(BTreeMap<&'a PeerId, BTreeMap<Urn, &'a ObjectId>>);

impl<'a, Urn> DelegateIds<'a, Urn>
where
    Urn: Ord,
{
    pub fn for_remote(&'a self, peer: &PeerId) -> impl Fn(&Urn) -> Option<&'a ObjectId> {
        let ids = self.0.get(peer);
        move |urn| ids.and_then(|x| x.get(urn).copied())
    }
}

impl<'a, T, Urn> FromIterator<&'a FilteredRef<'a, T>> for DelegateIds<'a, Urn>
where
    Urn: ids::Urn + Ord,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = &'a FilteredRef<'a, T>>,
    {
        use either::Either::Left;
        use refs::{parsed::Rad, Parsed};

        let inner = iter
            .into_iter()
            .filter_map(|r| {
                let (name, oid) = r.inner.unpack();
                match refs::parse(name.as_ref())? {
                    Parsed {
                        inner: Left(Rad::Ids { urn }),
                        ..
                    } => Some((r.remote_id.as_ref(), urn, oid)),

                    _ => None,
                }
            })
            .fold(BTreeMap::new(), |mut acc, (remote_id, urn, oid)| {
                acc.entry(remote_id)
                    .or_insert_with(BTreeMap::new)
                    .insert(urn, oid);
                acc
            });

        Self(inner)
    }
}
