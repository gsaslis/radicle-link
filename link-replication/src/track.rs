// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use crate::{PeerId, Urn};

pub trait Tracking {
    type Urn: Urn;
    type Tracked: Iterator<Item = Result<PeerId, Self::Error>>;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Track `id` in the context of `urn`, or the current [`Urn`].
    fn track(&self, id: &PeerId, urn: Option<&Self::Urn>) -> Result<(), Self::Error>;

    /// All tracked [`PeerId`]s in the context of `urn`, or the current [`Urn`].
    fn tracked(&self, urn: Option<&Self::Urn>) -> Self::Tracked;
}
