// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

//! Replication steps without their preconditions checked. Public for testing.

use std::{collections::BTreeSet, fmt::Debug, marker::PhantomData};

use bstr::BString;
use itertools::Itertools as _;
use link_crypto::PeerId;

use super::Success;
use crate::{
    error,
    exec,
    fetch,
    ids,
    peek,
    refs,
    sigrefs,
    validate,
    Applied,
    Error,
    Identities,
    LocalIdentity,
    LocalPeer,
    Net,
    ObjectId,
    Policy,
    Refdb,
    SignedRefs,
    SymrefTarget,
    Tracking,
    Update,
    Updated,
    Urn as _,
    VerifiedIdentity as _,
};

pub fn pull<C>(
    cx: &mut C,
    id: C::VerifiedIdentity,
    remote_id: PeerId,
    whoami: Option<LocalIdentity>,
) -> Result<Success<<C as Identities>::Urn>, Error>
where
    C: Identities + LocalPeer + Net + Refdb + SignedRefs + Tracking<Urn = <C as Identities>::Urn>,
    <C as SignedRefs>::Oid: Debug + Send + Sync,
    <C as Identities>::Urn: Debug + Ord,
{
    let local_id = *LocalPeer::id(cx);
    let delegates = id.delegate_ids();
    let tracked = {
        let mut tracked_here = Tracking::tracked(cx, None).collect::<Result<BTreeSet<_>, _>>()?;
        let mut tracked_there =
            Tracking::tracked(cx, Some(&id.urn())).collect::<Result<BTreeSet<_>, _>>()?;
        let mut transitive = delegates
            .iter()
            .map(|did| SignedRefs::load(cx, did, 3))
            .filter_map_ok(|x| x.map(|y| y.remotes))
            .fold_ok(BTreeSet::new(), |mut acc, mut remotes| {
                acc.append(&mut remotes);
                acc
            })?;

        tracked_here.append(&mut tracked_there);
        tracked_here.append(&mut transitive);

        tracked_here
            .into_iter()
            .filter(|id| !(delegates.contains(id) || id == &local_id))
            .collect::<BTreeSet<_>>()
    };

    // Peek
    info!("fetching verification refs");
    let exec::Out {
        spec:
            peek::ForFetch {
                local_id,
                remote_id,
                delegates,
                tracked,
            },
        mut applied,
        ..
    } = exec::exec(
        cx,
        peek::ForFetch {
            local_id,
            remote_id,
            delegates: delegates.into_inner(),
            tracked,
        },
    )?;

    // Now that we should have all delegate identity branches, see which one is
    // most recent, or if they forked.
    //
    // We may not yet have `rad/id`, so exclude our own id from the delegates if
    // present.
    let requires_confirmation = {
        info!("checking identity confirmation");
        let newest = ids::newest(cx, delegates.iter().filter(move |id| *id != &local_id))?;
        match newest {
            // Filtered delegates was empty, ie. delegates contains only
            // LocalPeer::id
            None => false,
            Some(newest) => match setup_rad(cx, newest, whoami) {
                Ok(mut ap) => {
                    applied.append(&mut ap);
                    false
                },
                Err(error::OwnRad::ConfirmationRequired) => true,
                Err(e) => return Err(Box::new(e)),
            },
        }
    };

    // Fetch
    info!("fetching data");
    let exec::Out {
        applied: mut ap, ..
    } = exec::exec(
        cx,
        fetch::Fetch {
            local_id,
            remote_id,
            signed_refs: sigrefs::combined(
                cx,
                sigrefs::Select {
                    must: &delegates,
                    may: &tracked,
                    cutoff: 3,
                },
            )?,
        },
    )?;
    applied.append(&mut ap);

    // Update our sigrefs
    info!("updating sigrefs");
    if let Some(oid) = SignedRefs::update(cx)? {
        applied.updated.push(Updated::Direct {
            name: BString::from(refs::Signed.as_str()),
            target: oid.into(),
        });
    }
    let signed_refs = sigrefs::combined(
        cx,
        sigrefs::Select {
            must: &delegates,
            may: &tracked,
            cutoff: 3,
        },
    )?;

    // Post-validate
    info!("validating");
    let validation = validate(cx, &signed_refs)?;
    if !validation.is_empty() {
        for warn in &validation {
            warn!("{}", warn)
        }
        //panic!("validation failures")
    }

    Ok(Success {
        applied,
        requires_confirmation,
        validation,
        _marker: PhantomData,
    })
}

#[tracing::instrument(level = "debug", skip(cx, theirs, whoami), err)]
pub fn setup_rad<C>(
    cx: &mut C,
    theirs: C::VerifiedIdentity,
    whoami: Option<LocalIdentity>,
) -> Result<Applied<'static>, error::OwnRad<C::VerifiedIdentity>>
where
    C: Identities + LocalPeer + Refdb + Tracking<Urn = <C as Identities>::Urn>,
    <C as Identities>::Urn: Debug,
{
    let newest = match ids::current(cx).map_err(error::OwnRad::Current)? {
        // `rad/id` exists, delegates to the local peer id, and is not at the
        // same revision as `theirs`
        Some(ours)
            if ours.delegate_ids().contains(LocalPeer::id(cx))
                && ours.revision() != theirs.revision() =>
        {
            // Check which one is more recent
            let tip = ours.content_id();
            let newer = Identities::newer(cx, ours, theirs)?;
            // Theirs is ahead, so we need to confirm
            if newer.content_id().as_ref() != tip.as_ref() {
                return Err(error::OwnRad::ConfirmationRequired);
            }
            // Ours is ahead, so use that
            else {
                newer
            }
        }

        // Otherwise, theirs:
        //
        // * `rad/id` does not exist, so no other choice
        // * local peer does not have a say, so we want theirs
        // * the revisions are equal, so it doesn't matter
        _ => theirs,
    };

    fn no_indirects<Urn: Debug>(urn: &Urn) -> Option<ObjectId> {
        debug_assert!(false, "tried to resolve indirect delegation {:?}", urn);
        None
    }

    let mut up = Vec::new();
    for urn in newest.delegate_urns() {
        let urn_enc = urn.encode_id();
        let delegate =
            Identities::verify_urn(cx, &urn, no_indirects).map_err(|e| error::OwnRad::Verify {
                urn: urn_enc.clone(),
                source: Box::new(e),
            })?;
        // Make sure we got 'em tracked
        for id in delegate.delegate_ids() {
            // Track id for the current Urn
            Tracking::track(cx, &id, None).map_err(|e| error::OwnRad::Track {
                id,
                source: Box::new(e),
            })?;
            // And also the delegate Urn
            Tracking::track(cx, &id, Some(&urn)).map_err(|e| error::OwnRad::TrackUrn {
                urn: urn_enc.clone(),
                id,
                source: Box::new(e),
            })?;
        }
        // Symref `rad/ids/$urn` -> refs/namespaces/$urn/refs/rad/id, creating
        // the target ref if it doesn't exist.
        up.push(Update::Symbolic {
            name: BString::from(format!("refs/rad/ids/{}", urn_enc)).into(),
            target: SymrefTarget {
                name: refs::Namespaced {
                    namespace: Some(BString::from(urn_enc).into()),
                    refname: refs::RadId.into(),
                },
                target: delegate.content_id().as_ref().to_owned(),
            },
            type_change: Policy::Allow,
        });
    }

    // Update `rad/self` in the same transaction
    if let Some(local_id) = whoami {
        up.push(Update::Direct {
            name: refs::RadSelf.into(),
            target: local_id.tip,
            no_ff: Policy::Reject,
        })
    }

    // Lastly, point `rad/id` to `newest.content_id`
    up.push(Update::Direct {
        name: refs::RadId.into(),
        target: newest.content_id().as_ref().to_owned(),
        no_ff: Policy::Reject,
    });

    Refdb::update(cx, up).map_err(|e| error::OwnRad::Tx(Box::new(e)))
}
