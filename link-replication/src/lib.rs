// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

#![allow(private_intra_doc_links, incomplete_features)]
#![warn(clippy::extra_unused_lifetimes)]
#![deny(broken_intra_doc_links)]
#![feature(bool_to_option, generic_associated_types)]

use std::{fmt::Debug, marker::PhantomData};

#[macro_use]
extern crate async_trait;
#[macro_use]
extern crate tracing;

use link_crypto::PeerId;

pub mod error;
pub use error::{Error, ErrorBox};

pub mod fetch;
pub mod internal;
pub mod io;
pub mod peek;
pub mod refs;

mod exec;
use exec::{Layout, UpdateTips};

mod ids;
pub use ids::{Identities, LocalIdentity, Urn, VerifiedIdentity};

mod odb;
pub use odb::Odb;

mod refdb;
pub use refdb::{Applied, Policy, Refdb, SymrefTarget, Update, Updated};

mod sigrefs;
pub use sigrefs::{SignedRefs, Sigrefs};

mod track;
pub use track::Tracking;

mod transmit;
pub use transmit::{FilteredRef, Negotiation, Net, WantsHaves};

mod validation;
pub use validation::validate;

// Re-exports
pub use git_repository::refs::{namespace, Namespace};
pub use link_git_protocol::{oid, ObjectId};

#[derive(Debug)]
pub struct Success<Urn> {
    applied: Applied<'static>,
    requires_confirmation: bool,
    validation: Vec<error::Validation>,
    _marker: PhantomData<Urn>,
}

impl<Urn> Success<Urn>
where
    Urn: ids::Urn,
{
    pub fn updated_refs(&self) -> &[Updated] {
        &self.applied.updated
    }

    pub fn rejected_updates(&self) -> &[Update<'static>] {
        &self.applied.rejected
    }

    pub fn urns_created(&self) -> impl Iterator<Item = Urn> + '_ {
        use refs::component::*;

        self.applied
            .updated
            .iter()
            .filter_map(|update| match update {
                Updated::Symbolic { target, .. } => {
                    let id = match target.splitn(7, refs::is_separator).collect::<Vec<_>>()[..] {
                        [REFS, NAMESPACES, id, REFS, RAD, ID] => Some(id),
                        _ => None,
                    }?;
                    let id = std::str::from_utf8(id).ok()?;
                    Urn::try_from_id(id).ok()
                },

                _ => None,
            })
    }

    pub fn requires_confirmation(&self) -> bool {
        self.requires_confirmation
    }

    pub fn validation_errors(&self) -> &[error::Validation] {
        &self.validation
    }
}

pub trait LocalPeer {
    fn id(&self) -> &PeerId;
}

#[tracing::instrument(skip(cx, whoami), fields(local_id = %LocalPeer::id(cx)))]
pub fn pull<C>(
    cx: &mut C,
    remote_id: PeerId,
    whoami: Option<LocalIdentity>,
) -> Result<Success<<C as Identities>::Urn>, Error>
where
    C: Identities + LocalPeer + Net + Refdb + SignedRefs + Tracking<Urn = <C as Identities>::Urn>,
    <C as SignedRefs>::Oid: Debug + Send + Sync,
    <C as Identities>::Urn: Debug + Ord,
{
    if LocalPeer::id(cx) == &remote_id {
        return Err("cannot replicate from self".into());
    }
    let id = ids::current(cx)?.ok_or("pull: missing `rad/id`")?;
    internal::pull(cx, id, remote_id, whoami)
}

#[tracing::instrument(skip(cx, whoami), fields(local_id = %LocalPeer::id(cx)))]
pub fn clone<C>(
    cx: &mut C,
    remote_id: PeerId,
    whoami: Option<LocalIdentity>,
) -> Result<Success<<C as Identities>::Urn>, Error>
where
    C: Identities + LocalPeer + Net + Refdb + SignedRefs + Tracking<Urn = <C as Identities>::Urn>,
    <C as SignedRefs>::Oid: Debug + Send + Sync,
    <C as Identities>::Urn: Debug + Ord,
{
    info!("fetching initial verification refs");
    let exec::Out {
        refs, mut applied, ..
    } = exec::exec(cx, peek::ForClone { remote_id })?;
    // FIXME: we do this already in `UpdateTips::prepare`
    let id_ref = refs
        .iter()
        .find(|r| r.remote_id.as_ref() == &remote_id && r.inner.unpack().0.ends_with(b"rad/id"))
        .ok_or("clone: missing `rad/id` of remote")?;
    let id = Identities::verify(
        cx,
        id_ref.inner.unpack().1,
        refs.iter()
            .collect::<peek::DelegateIds<_>>()
            .for_remote(&remote_id),
    )?;

    let mut success = internal::pull(cx, id, remote_id, whoami)?;
    applied.append(&mut success.applied);
    success.applied = applied;
    Ok(success)
}
