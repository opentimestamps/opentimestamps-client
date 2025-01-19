# Copyright (C) 2017-2018 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import sys

import argparse
import base64
import bitcoin
import logging
import subprocess
import shutil

import git
from opentimestamps.core.git import GitTreeTimestamper

from opentimestamps.core.timestamp import Timestamp
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext, BytesDeserializationContext

import otsclient.args
from otsclient.git import hash_signed_commit, write_ascii_armored, deserialize_ascii_armored_timestamp

def main():
    parser = otsclient.args.make_common_options_arg_parser()

    parser.add_argument("-g", "--gpg-program", action="store", default=shutil.which("gpg") or "/usr/bin/gpg",
                        help="Path to the GnuPG binary (default %(default)s)")

    parser.add_argument('-c','--calendar', metavar='URL', dest='calendar_urls', action='append', type=str,
                        default=["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org", "https://a.pool.eternitywall.com","https://ots.btc.catallaxy.com"],
                        help='Create timestamp with the aid of a remote calendar. May be specified multiple times. Default: %(default)r')
    parser.add_argument('-b','--btc-wallet', dest='use_btc_wallet', action='store_true',
                        help='Create timestamp locally with the local Bitcoin wallet.')
    parser.add_argument("gpgargs", nargs=argparse.REMAINDER,
                        help='Arguments passed to GnuPG binary')

    parser.add_argument("--timeout", type=int, default=5,
                                  help="Timeout before giving up on a calendar. "
                                       "Default: %(default)d")

    parser.add_argument("-m", type=int, default="2",
                                  help="Commitments are sent to remote calendars,"
                                       "in the event of timeout the timestamp is considered "
                                       "done if at least M calendars replied. "
                                       "Default: %(default)s")

    parser.add_argument('--rehash-trees', action='store_true',
                        help=argparse.SUPPRESS)


    args = otsclient.args.handle_common_options(parser.parse_args(), parser)

    logging.basicConfig(format='ots: %(message)s')

    args.verbosity = args.verbose - args.quiet
    if args.verbosity == 0:
        logging.root.setLevel(logging.INFO)
    elif args.verbosity > 0:
        logging.root.setLevel(logging.DEBUG)
    elif args.verbosity == -1:
        logging.root.setLevel(logging.WARNING)
    elif args.verbosity < -1:
        logging.root.setLevel(logging.ERROR)

    if len(args.gpgargs) == 0 or args.gpgargs[0] != '--':
        parser.error("You need to have '--' as the last argument; see docs")

    args.gpgargs = args.gpgargs[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument("-bsau", action="store")
    parser.add_argument("--verify", action="store")
    gpgargs = parser.parse_known_args(args.gpgargs)[0]

    if gpgargs.bsau:
        with subprocess.Popen([args.gpg_program] + args.gpgargs, stdin=subprocess.PIPE, stdout=subprocess.PIPE) as gpg_proc:
            logging.debug("Reading Git commit")
            git_commit = sys.stdin.buffer.read()

            logging.debug("Git commit: %r" % git_commit)

            # FIXME: can this fail to write all bytes?
            n = gpg_proc.stdin.write(git_commit)
            logging.debug("Wrote %d bytes to GnuPG out of %d" % (n, len(git_commit)))
            gpg_proc.stdin.close()

            gpg_sig = gpg_proc.stdout.read()

            # GnuPG produces no output on failure
            if not gpg_sig:
                sys.exit(1)

            logging.debug("PGP sig: %r" % gpg_sig)

            # Timestamp the commit and tag together
            signed_commit_timestamp = Timestamp(hash_signed_commit(git_commit, gpg_sig))
            final_timestamp = signed_commit_timestamp

            # with git tree rehashing
            minor_version = 1

            # CWD will be the git repo, so this should get us the right one
            repo = git.Repo(".")

            hextree_start = None
            if git_commit.startswith(b'tree '):
                hextree_start = 5
            elif git_commit.startswith(b'object '):
                # I believe this is always a git tag
                hextree_start = 7
            else:
                raise AssertionError("Don't know what to do with %r" % git_commit)

            hextree = git_commit[hextree_start:hextree_start + 20*2].decode()
            tree = repo.tree(hextree)
            tree.path = ''

            tree_stamper = GitTreeTimestamper(tree)

            final_timestamp = signed_commit_timestamp.ops.add(OpAppend(tree_stamper.timestamp.msg)).ops.add(OpSHA256())

            otsclient.cmds.create_timestamp(final_timestamp, args.calendar_urls, args)

            if args.wait:
                # Interpreted as override by the upgrade command
                # FIXME: need to clean this bad abstraction up!
                args.calendar_urls = []
                otsclient.cmds.upgrade_timestamp(signed_commit_timestamp, args)

            sys.stdout.buffer.write(gpg_sig)
            write_ascii_armored(signed_commit_timestamp, sys.stdout.buffer, minor_version)

    elif gpgargs.verify:
        # Verify
        with open(gpgargs.verify, 'rb') as gpg_sig_fd:
            gpg_sig = gpg_sig_fd.read()
            git_commit = sys.stdin.buffer.read()

            (major_version, minor_version, timestamp) = deserialize_ascii_armored_timestamp(git_commit, gpg_sig)
            if timestamp is None:
                print("OpenTimestamps: No timestamp found", file=sys.stderr)
            else:
                good = otsclient.cmds.verify_timestamp(timestamp, args)

                if good:
                    logging.info("Good timestamp")
                else:
                    logging.warning("Could not verify timestamp!")
            sys.stderr.flush()

            logging.debug("Running GnuPG binary: %r" % ([args.gpg_program] + args.gpgargs))
            with subprocess.Popen([args.gpg_program] + args.gpgargs, stdin=subprocess.PIPE) as gpg_proc:
                gpg_proc.stdin.write(git_commit)
                gpg_proc.stdin.close()

# vim:syntax=python filetype=python
