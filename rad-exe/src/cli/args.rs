// Copyright © 2021 The Radicle Link Contributors
//
// This file is part of radicle-link, distributed under the GPLv3 with Radicle
// Linking Exception. For full terms see the included LICENSE file.

use std::env;

use structopt::StructOpt;

use librad::profile::ProfileId;

/// `--rad-profile` command line name
pub const RAD_PROFILE_ARG: &str = "--rad-profile";

/// `--rad-quiet` command line name
pub const RAD_QUIET_ARG: &str = "--rad-quiet";

/// `--rad-verbose` command line name
pub const RAD_VERBOSE_ARG: &str = "--rad-verbose";

#[derive(Debug, StructOpt)]
pub struct Args {
    /// The profile identifier, if not given then the currently active profile
    /// is used
    #[structopt(long)]
    pub rad_profile: Option<ProfileId>,

    /// No output printed to stdout
    #[structopt(long)]
    pub rad_quiet: bool,

    /// Use verbose output
    #[structopt(long)]
    pub rad_verbose: bool,

    #[structopt(subcommand)]
    pub command: Command,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    /// This is just a stub, sshhhh
    // TODO(finto): Fill in core commands
    Profile,
    #[structopt(external_subcommand)]
    External(Vec<String>),
}

/// If an external subcommand is called, we sanitise the global arguments according to the rules defined in [RFC 698](https://github.com/radicle-dev/radicle-link/blob/master/docs/rfc/0698-cli-infrastructure.adoc#global-parameters).
///
/// The rules are summarised as:
///   * The first value takes precedence, e.g. `rad --rad-profile deaf xxx
///     --rad-profile beef` will result in `deaf`
///   * Command line arguments take precedence over environment variables, e.g.
///     `RAD_PROFILE=deaf rad --rad-profile def` will result in `beef`
pub fn sanitise_globals(mut args: Args) -> Args {
    match &mut args.command {
        Command::External(external) => {
            sanitise_option(
                RAD_PROFILE_ARG,
                "RAD_PROFILE",
                args.rad_profile.clone().map(|id| id.to_string()),
                external,
            );

            sanitise_flag(RAD_QUIET_ARG, "RAD_QUIET", args.rad_quiet, external);

            sanitise_flag(RAD_VERBOSE_ARG, "RAD_VERBOSE", args.rad_quiet, external);

            args
        },
        _ => args,
    }
}

fn sanitise_option(arg: &str, env: &str, global: Option<String>, external: &mut Vec<String>) {
    let env = env::var(env).ok();
    let ex_arg = {
        let index = find_arg(arg, external);
        match index {
            Some(index) => {
                external.remove(index);
                Some(external.remove(index))
            },
            None => None,
        }
    };
    let value = global.or(ex_arg).or(env);
    if let Some(value) = value {
        external.extend_from_slice(&[arg.to_string(), value]);
    }
}

fn sanitise_flag(arg: &str, env: &str, val: bool, external: &mut Vec<String>) {
    let env = env::var(env).ok();
    let ex_arg = {
        let index = find_arg(arg, external);
        match index {
            Some(index) => {
                external.remove(index);
                Some(true)
            },
            None => None,
        }
    };
    let value = val || ex_arg.is_some() || env.is_some();
    if value {
        external.extend_from_slice(&[arg.to_string()]);
    }
}

/// Get the position of an argument name, if present.
pub fn find_arg(needle: &str, external: &[String]) -> Option<usize> {
    external
        .iter()
        .enumerate()
        .find(|(_, arg)| arg.as_str() == needle)
        .map(|(i, _)| i)
}
