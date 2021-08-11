// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::{
    borrow::Cow,
    collections::{BTreeSet, HashSet},
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use bstr::ByteSlice as _;
use link_crypto::PeerId;
use link_git_protocol::{ObjectId, Ref};

use crate::{refs, Refdb};

#[async_trait(?Send)]
pub trait Net {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn run_fetch<N, T>(
        &self,
        neg: N,
    ) -> Result<(N, Vec<FilteredRef<'static, T>>), Self::Error>
    where
        N: Negotiation<T> + Send,
        T: Send + 'static;
}

pub trait Negotiation<T = Self> {
    /// The `ref-prefix`es to send with `ls-refs`.
    fn ref_prefixes(&self) -> Vec<refs::Scoped<'_, '_>>;

    /// Filter a remote-advertised [`Ref`].
    ///
    /// Return `Some` if the ref should be considered, `None` otherwise. This
    /// method may be called with the response of `ls-refs`, the `wanted-refs`
    /// of a `fetch` response, or both.
    fn ref_filter<'a>(&'a self, r: &'a Ref) -> Option<FilteredRef<'a, T>>;

    /// Assemble the `want`s and `have`s for a `fetch`, retaining the refs which
    /// would need updating after the `fetch` succeeds.
    ///
    /// The `refs` are the advertised refs from executing `ls-refs`, filtered
    /// through [`Negotiation::ref_filter`].
    fn wants_haves<'a, R: Refdb>(
        &self,
        db: &R,
        refs: impl IntoIterator<Item = FilteredRef<'a, T>>,
    ) -> Result<WantsHaves<'a, T>, R::FindError>;
}

pub struct WantsHaves<'a, T: ?Sized> {
    pub wanted: HashSet<FilteredRef<'a, T>>,
    pub wants: BTreeSet<ObjectId>,
    pub haves: BTreeSet<ObjectId>,
}

#[derive(Clone)]
pub struct FilteredRef<'a, T: ?Sized> {
    pub remote_id: Cow<'a, PeerId>,
    pub inner: Cow<'a, Ref>,
    _marker: PhantomData<T>,
}

impl<T> PartialEq for FilteredRef<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.remote_id == other.remote_id && self.inner == other.inner
    }
}

impl<T> Eq for FilteredRef<'_, T> {}

impl<T> Hash for FilteredRef<'_, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.remote_id.hash(state);
        self.inner.hash(state);
    }
}

impl<'a, T> FilteredRef<'a, T> {
    pub fn new(remote_id: Cow<'a, PeerId>, inner: &'a Ref) -> Self {
        Self {
            remote_id,
            inner: Cow::Borrowed(inner),
            _marker: PhantomData,
        }
    }

    pub fn as_scoped(&self, remote_id: &PeerId) -> refs::Scoped<'_, '_> {
        refs::scoped(&self.remote_id, remote_id, self.inner.unpack().0.as_bstr())
    }

    pub fn into_owned<'b>(self) -> FilteredRef<'b, T> {
        FilteredRef {
            remote_id: Cow::Owned(self.remote_id.into_owned()),
            inner: Cow::Owned(self.inner.into_owned()),
            _marker: PhantomData,
        }
    }
}
