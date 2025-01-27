// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use radicle_git_ext::RefspecPattern;

use crate::git::tracking::reference::RefName;

pub mod previous_value;
pub use previous_value::{PreviousError, PreviousValue};

/// A reference loaded from a reference database.
///
/// The reference is expected to be a direct reference that points to a blob
/// containing a [`crate::git::config::Config`].
#[derive(Debug)]
pub struct Ref<'a, Oid: ToOwned + Clone> {
    pub name: RefName<'a, Oid>,
    pub target: Oid,
}

pub trait Read<'a> {
    type FindError: std::error::Error + Send + Sync + 'static;
    type ReferencesError: std::error::Error + Send + Sync + 'static;
    type IterError: std::error::Error + Send + Sync + 'static;

    type Oid: Clone + 'static;
    type References: Iterator<Item = Result<Ref<'a, Self::Oid>, Self::IterError>>;

    /// Get a [`Ref`] by `name`, returning `None` if no such reference exists.
    fn find_reference(
        &self,
        name: &RefName<'_, Self::Oid>,
    ) -> Result<Option<Ref<Self::Oid>>, Self::FindError>;

    /// Get all [`Ref`]s that match the given `refspec`.
    #[allow(clippy::type_complexity)]
    fn references(
        &'a self,
        refspec: &RefspecPattern,
    ) -> Result<Self::References, Self::ReferencesError>;
}

pub trait Write {
    type TxnError: std::error::Error + Send + Sync + 'static;

    type Oid: ToOwned + Clone;

    /// Apply the provided ref updates.
    ///
    /// This should be a transaction: either all updates are applied, or none.
    fn update<'a, I>(&self, updates: I) -> Result<Applied<'a, Self::Oid>, Self::TxnError>
    where
        I: IntoIterator<Item = Update<'a, Self::Oid>>;
}

#[derive(Clone, Debug)]
pub enum Update<'a, Oid: ToOwned + Clone> {
    /// Create or update the reference given by `name`, pointing to the given
    /// `target`. This will succeed iff the `previous` condition given
    /// succeeds.
    Write {
        name: RefName<'a, Oid>,
        target: Oid,
        previous: PreviousValue<Oid>,
    },
    /// Delete the reference given by `name`. This will succeed iff the
    /// `previous` condition given succeeds.
    Delete {
        name: RefName<'a, Oid>,
        previous: PreviousValue<Oid>,
    },
}

/// The collected applications during a call to [`Write::update`].
pub struct Applied<'a, Oid: ToOwned + Clone> {
    /// The successful [`Update`]s.
    pub updates: Vec<Updated<'a, Oid>>,
    /// The rejected [`Update`]s based on their [`PreviousValue`].
    pub rejections: Vec<PreviousError<Oid>>,
}

impl<'a, Oid: ToOwned + Clone> Default for Applied<'a, Oid> {
    fn default() -> Self {
        Applied {
            updates: Vec::new(),
            rejections: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Updated<'a, Oid: ToOwned + Clone> {
    /// The reference, given by `name`, was written with `target` value.
    Written { name: RefName<'a, Oid>, target: Oid },
    /// The reference, given by `name` was deleted. The `previous` value is
    /// returned if it was available.
    Deleted {
        name: RefName<'a, Oid>,
        previous: Oid,
    },
}
