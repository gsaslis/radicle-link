// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::fmt::Debug;

use futures_lite::future::block_on;
use tracing::Instrument as _;

use crate::{error, Applied, Error, FilteredRef, Identities, Negotiation, Net, Refdb, Update};

pub(crate) trait UpdateTips<T = Self> {
    fn prepare<'a, I>(
        &self,
        ids: &I,
        refs: &'a [FilteredRef<'a, T>],
    ) -> Result<Vec<Vec<Update<'a>>>, error::Prepare<I::VerificationError>>
    where
        I: Identities,
        I::Urn: Ord;
}

pub(crate) trait Layout<T = Self> {
    /// Validate that all advertised refs conform to an expected layout.
    ///
    /// The supplied `refs` are both `ls-ref`-advertised refs and `wanted-refs`
    /// filtered through [`Negotiation::ref_filter`].
    fn pre_validate<'a>(&self, refs: &'a [FilteredRef<'a, T>]) -> Result<(), error::Layout>;
}

pub struct Out<S> {
    /// What moves in must move out.
    pub spec: S,
    /// The set of refs considered for the update tips phase.
    pub refs: Vec<FilteredRef<'static, S>>,
    /// The result of the update tips phase.
    pub applied: Applied<'static>,
}

#[tracing::instrument(level = "debug", skip(cx), err)]
pub(crate) fn exec<C, S>(cx: &mut C, spec: S) -> Result<Out<S>, Error>
where
    C: Identities + Net + Refdb,
    S: Layout + Negotiation + UpdateTips + Debug + Send + Sync + 'static,
    <C as Identities>::Urn: Ord,
{
    // Ensure negotiation is accurate
    Refdb::reload(cx)?;
    let (spec, refs) = block_on(Net::run_fetch(cx, spec).in_current_span())?;
    Layout::pre_validate(&spec, &refs)?;
    let updates = UpdateTips::prepare(&spec, cx, &refs)?;
    // FIXME: maybe move `refs` in and out of `prepare`, so we don't have to
    // clone the rejected updates?
    let mut applied = Applied::default();
    for tx in updates {
        let mut ap = Refdb::update(cx, tx)?.into_owned();
        applied.append(&mut ap);
    }

    for re in &applied.rejected {
        debug!("rejected: {:?}", re);
    }
    for up in &applied.updated {
        debug!("updated: {:?}", up);
    }

    Ok(Out {
        spec,
        refs,
        applied,
    })
}
