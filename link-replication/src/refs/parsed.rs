// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::{
    convert::Infallible,
    fmt::{self, Display},
    iter,
};

use bstr::BStr;
use either::Either;
use link_crypto::PeerId;

use super::{is_separator, lit::component::*};
use crate::ids;

pub struct Parsed<'a, Urn> {
    pub remote: Option<PeerId>,
    pub inner: Either<Rad<Urn>, Refs<'a>>,
}

pub enum Rad<Urn> {
    Id,
    Me, // self
    SignedRefs,
    Ids { urn: Urn },
}

pub struct Refs<'a> {
    pub cat: Cat<'a>,
    pub name: Vec<&'a [u8]>,
}

pub enum Cat<'a> {
    Heads,
    Notes,
    Tags,
    Unknown(&'a [u8]),
}

impl Cat<'_> {
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl Display for Cat<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Heads => f.write_str("heads"),
            Self::Notes => f.write_str("notes"),
            Self::Tags => f.write_str("tags"),
            Self::Unknown(x) => match std::str::from_utf8(x) {
                Ok(s) => f.write_str(s),
                Err(_) => write!(f, "{:?}", x),
            },
        }
    }
}

impl AsRef<[u8]> for Cat<'_> {
    fn as_ref(&self) -> &[u8] {
        use super::component::*;

        match self {
            Self::Heads => HEADS,
            Self::Notes => NOTES,
            Self::Tags => TAGS,
            Self::Unknown(x) => x,
        }
    }
}

pub struct Identity(String);

impl ids::Urn for Identity {
    type Error = Infallible;

    fn try_from_id(s: impl AsRef<str>) -> Result<Self, Self::Error> {
        Ok(Self(s.as_ref().to_owned()))
    }

    fn encode_id(&self) -> String {
        self.0.clone()
    }
}

pub fn parse<Urn>(orig: &BStr) -> Option<Parsed<'_, Urn>>
where
    Urn: ids::Urn,
{
    let mut iter = orig.split(is_separator);
    if iter.next()? != REFS {
        return None;
    }
    match iter.next()? {
        REMOTES => {
            let remote = iter
                .next()
                .and_then(|s| std::str::from_utf8(s).ok())
                .and_then(|s| s.parse::<PeerId>().ok())?;

            parse_prime(Some(remote), iter)
        },
        x => parse_prime(None, iter::once(x).chain(iter)),
    }
}

fn parse_prime<'a, Urn>(
    remote: Option<PeerId>,
    mut iter: impl Iterator<Item = &'a [u8]>,
) -> Option<Parsed<'a, Urn>>
where
    Urn: ids::Urn,
{
    match iter.next()? {
        [] => None,

        RAD => match iter.next()? {
            ID => Some(Parsed {
                remote,
                inner: Either::Left(Rad::Id),
            }),
            SELF => Some(Parsed {
                remote,
                inner: Either::Left(Rad::Me),
            }),
            SIGNED_REFS => Some(Parsed {
                remote,
                inner: Either::Left(Rad::SignedRefs),
            }),
            IDS => {
                let urn = iter
                    .next()
                    .and_then(|s| std::str::from_utf8(s).ok())
                    .and_then(|s| Urn::try_from_id(s).ok())?;
                Some(Parsed {
                    remote,
                    inner: Either::Left(Rad::Ids { urn }),
                })
            },

            _ => None,
        },

        x => {
            let name = iter.collect::<Vec<_>>();
            if name.is_empty() {
                None
            } else {
                Some(Parsed {
                    remote,
                    inner: Either::Right(Refs {
                        name,
                        cat: match x {
                            HEADS => Cat::Heads,
                            NOTES => Cat::Notes,
                            TAGS => Cat::Tags,
                            y => Cat::Unknown(y),
                        },
                    }),
                })
            }
        },
    }
}
