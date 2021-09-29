// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::{convert::Infallible, path::Path, sync::Arc};

use git_repository::{
    odb::{self, pack, Find as _, FindExt as _},
    traverse::commit::{ancestors, Ancestors},
};
use link_git_protocol::{
    oid,
    packwriter::{BuildThickener, Thickener},
    ObjectId,
};
use parking_lot::RwLock;

use crate::Error;

#[derive(Clone)]
pub struct Odb(Arc<RwLock<odb::linked::Store>>);

impl Odb {
    pub fn at(git_dir: impl AsRef<Path>) -> Result<Self, Error> {
        let store = odb::linked::Store::at(git_dir.as_ref().join("objects"))?;
        Ok(Self(Arc::new(RwLock::new(store))))
    }
}

impl Thickener for Odb {
    fn find_object<'a>(
        &self,
        id: ObjectId,
        buf: &'a mut Vec<u8>,
    ) -> Option<pack::data::Object<'a>> {
        self.0.read().find(id, buf, &mut pack::cache::Never).ok()
    }
}

impl BuildThickener for Odb {
    type Error = Infallible;
    type Thick = Self;

    fn build_thickener(&self) -> Result<Self::Thick, Self::Error> {
        Ok(self.clone())
    }
}

impl crate::odb::Odb for Odb {
    type LookupError = odb::compound::find::Error;
    type RevwalkError = ancestors::Error;
    type AddPackError = pack::bundle::init::Error;
    type ReloadError = odb::linked::init::Error;

    fn contains(&self, oid: impl AsRef<oid>) -> bool {
        self.0.read().contains(oid)
    }

    fn lookup<'a>(
        &self,
        oid: impl AsRef<oid>,
        buf: &'a mut Vec<u8>,
    ) -> Result<Option<crate::odb::Object<'a>>, Self::LookupError> {
        self.0
            .read()
            .try_find(oid, buf, &mut odb::pack::cache::Never)
            .map(|obj| obj.map(Into::into))
    }

    fn is_in_ancestry_path(
        &self,
        new: impl Into<ObjectId>,
        old: impl Into<ObjectId>,
    ) -> Result<bool, Self::RevwalkError> {
        let new = new.into();
        let old = old.into();

        // No need to take the lock
        if new == old {
            return Ok(true);
        }

        let odb = self.0.read();
        // Annoyingly, gitoxide returns an error if the tip is not known. While
        // we're at it, we can also fast-path the revwalk if the ancestor is
        // unknown.
        if !odb.contains(&new) || !odb.contains(&old) {
            return Ok(false);
        }
        let walk = Ancestors::new(Some(new), ancestors::State::default(), move |oid, buf| {
            odb.find_commit_iter(oid, buf, &mut odb::pack::cache::Never)
                .ok()
        });
        for parent in walk {
            if parent? == old {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn add_pack(&self, path: impl AsRef<Path>) -> Result<(), Self::AddPackError> {
        let bundle = pack::Bundle::at(path)?;
        self.0
            .write()
            .dbs
            .get_mut(0)
            .expect("odb must have at least one backend")
            .bundles
            .insert(0, bundle);

        Ok(())
    }

    fn reload(&self) -> Result<(), Self::ReloadError> {
        self.0.write().refresh()?;

        Ok(())
    }
}
