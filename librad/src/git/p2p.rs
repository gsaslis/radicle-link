// Copyright © 2019-2020 The Radicle Foundation <hello@radicle.foundation>
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

#[cfg(not(feature = "replication-v3"))]
pub mod header;
#[cfg(not(feature = "replication-v3"))]
pub mod transport;
pub mod url;

pub const URL_SCHEME: &str = "rad-p2p";
