// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::path::Path;

use git_repository::odb;
use link_git_protocol::{oid, ObjectId};

pub use git_repository::objs as object;

pub struct Object<'a> {
    pub kind: object::Kind,
    pub data: &'a [u8],
}

impl<'a> From<odb::data::Object<'a>> for Object<'a> {
    fn from(odb::data::Object { kind, data, .. }: odb::data::Object<'a>) -> Self {
        Self { kind, data }
    }
}

impl<'a> From<Object<'a>> for (object::Kind, &'a [u8]) {
    fn from(Object { kind, data }: Object<'a>) -> Self {
        (kind, data)
    }
}

pub trait Odb {
    type LookupError: std::error::Error + Send + Sync + 'static;
    type RevwalkError: std::error::Error + Send + Sync + 'static;
    type AddPackError: std::error::Error + Send + Sync + 'static;
    type ReloadError: std::error::Error + Send + Sync + 'static;

    /// Test if the given [`oid`] is present in any of the [`Odb`]'s backends.
    ///
    /// May return false negatives if the [`Odb`] hasn't loaded a packfile yet.
    /// It is advisable to call [`Odb::add_pack`] explicitly where possible.
    ///
    /// Note that this behaves like [`std::path::Path::is_file`]: I/O errors
    /// translate to `false`.
    fn contains(&self, oid: impl AsRef<oid>) -> bool;

    fn lookup<'a>(
        &self,
        oid: impl AsRef<oid>,
        buf: &'a mut Vec<u8>,
    ) -> Result<Option<Object<'a>>, Self::LookupError>;

    fn is_in_ancestry_path(
        &self,
        new: impl Into<ObjectId>,
        old: impl Into<ObjectId>,
    ) -> Result<bool, Self::RevwalkError>;

    /// Make the [`Odb`] aware of a packfile.
    ///
    /// The [`Path`] may point to either the pack (_*.pack_) or index (_*.idx_).
    fn add_pack(&self, path: impl AsRef<Path>) -> Result<(), Self::AddPackError>;

    /// Reload all backends.
    fn reload(&self) -> Result<(), Self::ReloadError>;
}
