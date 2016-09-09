# Copyright (C) 2016 The OpenTimestamps developers
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
import binascii
import datetime
import logging
import os
import time
import urllib.request

import bitcoin
import bitcoin.rpc

from bitcoin.core import b2x, b2lx, lx, CTxOut, CTransaction
from bitcoin.core.script import CScript, OP_RETURN

from binascii import hexlify

from opentimestamps.core.notary import *
from opentimestamps.core.timestamp import *
from opentimestamps.core.op import *
from opentimestamps.core.serialize import *
from opentimestamps.timestamp import *
from opentimestamps.bitcoin import *
from opentimestamps.calendar import *


def create_timestamp(timestamp, calendar_urls, setup_bitcoin=False):
    """Create a timestamp

    calendar_urls - List of calendar's to use
    setup_bitcoin - False if Bitcoin timestamp not desired; set to
                    args.setup_bitcoin() otherwise.
    """

    if setup_bitcoin:
        proxy = setup_bitcoin()

        unfunded_tx = CTransaction([], [CTxOut(0, CScript([OP_RETURN, timestamp.msg]))])
        r = proxy.fundrawtransaction(unfunded_tx)  # FIXME: handle errors
        funded_tx = r['tx']

        r = proxy.signrawtransaction(funded_tx)
        assert r['complete']
        signed_tx = r['tx']

        txid = proxy.sendrawtransaction(signed_tx)
        logging.info('Sent timestamp tx')

        blockhash = None
        while blockhash is None:
            logging.info('Waiting for timestamp tx %s to confirm...' % b2lx(txid))
            time.sleep(1)

            r = proxy.gettransaction(txid)

            if 'blockhash' in r:
                # FIXME: this will break when python-bitcoinlib adds RPC
                # support for gettransaction, due to formatting differences
                blockhash = lx(r['blockhash'])

        logging.info('Confirmed by block %s' % b2lx(blockhash))

        block = proxy.getblock(blockhash)

        # FIXME: as of v0.6.0 python-bitcoinlib doesn't support the verbose option
        # for getblock(header), so we have to go a bit low-level to get the block
        # height.
        r = proxy._call('getblock', b2lx(blockhash), True)
        blockheight = r['height']

        # We have a block hash! We can now generate the attestation from the block.
        block_timestamp = make_timestamp_from_block(timestamp.msg, block, blockheight)
        assert block_timestamp is not None
        timestamp.merge(block_timestamp)

    for calendar_url in calendar_urls:
        remote = RemoteCalendar(calendar_url)

        logging.info('Submitting to remote calendar %s' % calendar_url)
        calendar_timestamp = remote.submit(timestamp.msg)
        timestamp.merge(calendar_timestamp)


def stamp_command(args):
    # Create initial commitment ops for all files
    file_timestamps = []
    merkle_roots = []
    for fd in args.files:
        # FIXME: handle file IO errors
        file_timestamp = DetachedTimestampFile.from_fd(OpSHA256(), fd)

        # Add nonce
        #
        # Remember that the files - and their timestamps - might get separated
        # later, so if we didn't use a nonce for every file, the timestamp
        # would leak information on the digests of adjacent files.
        nonce_appended_stamp = file_timestamp.timestamp.ops.add(OpAppend(os.urandom(16)))
        merkle_root = nonce_appended_stamp.ops.add(OpSHA256())

        merkle_roots.append(merkle_root)
        file_timestamps.append(file_timestamp)

    merkle_tip = make_merkle_tree(merkle_roots)

    if not args.calendar_urls:
        # Neither calendar nor wallet specified; add default
        args.calendar_urls.append('https://pool.opentimestamps.org')

    create_timestamp(merkle_tip, args.calendar_urls, args.setup_bitcoin if args.use_btc_wallet else False)

    if args.wait:
        upgrade_timestamp(merkle_tip, args)
        logging.info("Timestamp complete; saving")

    for (in_file, file_timestamp) in zip(args.files, file_timestamps):
        timestamp_file_path = in_file.name + '.ots'

        try:
            with open(timestamp_file_path, 'xb') as timestamp_fd:
                ctx = StreamSerializationContext(timestamp_fd)
                file_timestamp.serialize(ctx)
        except IOError as exp:
            logging.error("Failed to create timestamp %r: %s" % (timestamp_file_path, exp))
            sys.exit(1)

def is_timestamp_complete(stamp, args):
    """Determine if timestamp is complete and can be verified"""
    for msg, attestation in stamp.all_attestations():
        if attestation.__class__ == BitcoinBlockHeaderAttestation:
            # FIXME: we should actually check this attestation, rather than
            # assuming it's valid
            return True
    else:
        return False

def upgrade_timestamp(timestamp, args):
    """Attempt to upgrade an incomplete timestamp to make it verifiable

    Returns True if the timestamp has changed, False otherwise.

    Note that this means if the timestamp that is already complete, False will
    be returned as nothing has changed.
    """

    def directly_verified(stamp):
        if stamp.attestations:
            yield stamp
        else:
            for result_stamp in stamp.ops.values():
                yield from directly_verified(result_stamp)
        yield from ()

    def get_attestations(stamp):
        return set(attest for msg, attest in stamp.all_attestations())


    changed = False

    # First, check the cache for upgrades to this timestamp. Since the cache is
    # local, we do this very agressively, checking every single sub-timestamp
    # against the cache.
    def walk_stamp(stamp):
        yield stamp
        for sub_stamp in stamp.ops.values():
            yield from walk_stamp(sub_stamp)

    existing_attestations = get_attestations(timestamp)
    for sub_stamp in walk_stamp(timestamp):
        try:
            cached_stamp = args.cache[sub_stamp.msg]
        except KeyError:
            continue
        sub_stamp.merge(cached_stamp)

    new_attestations_from_cache = get_attestations(timestamp).difference(existing_attestations)
    if len(new_attestations_from_cache):
        changed = True
        logging.info("Got %d attestation(s) from cache" % len(new_attestations_from_cache))
        existing_attestations.update(new_attestations_from_cache)
        for new_att in new_attestations_from_cache:
            logging.debug("    %r" % new_att)

    while not is_timestamp_complete(timestamp, args):
        # Check remote calendars for upgrades.
        #
        # This time we only check PendingAttestations - we can't be as
        # agressive.
        found_new_attestations = False
        for sub_stamp in directly_verified(timestamp):
            for attestation in sub_stamp.attestations:
                if attestation.__class__ == PendingAttestation:
                    calendar_urls = args.calendar_urls
                    if calendar_urls:
                        logging.debug("Attestation URI %s overridden by user-specified remote calendar(s)" % attestation.uri)
                    else:
                        if args.whitelist is None:
                            logging.info("Ignoring attestation from calendar %s: remote calendars disabled" % attestation.uri)
                            continue
                        elif attestation.uri in args.whitelist:
                            calendar_urls = [attestation.uri]
                        else:
                            logging.info("Ignoring attestation from calendar %s: not whitelisted" % attestation.uri)
                            continue

                    commitment = sub_stamp.msg
                    for calendar_url in calendar_urls:
                        logging.debug("Checking calendar %s for %s" % (attestation.uri, b2x(commitment)))
                        calendar = RemoteCalendar(calendar_url)

                        try:
                            upgraded_stamp = calendar.get_timestamp(commitment)
                        except KeyError:
                            logging.info("Calendar %s: No timestamp found" % attestation.uri)
                            continue
                        except Exception as exp:
                            logging.info("Calendar %s: %r" % (attestation.uri, exp))
                            continue

                        new_attestations = get_attestations(upgraded_stamp).difference(existing_attestations)

                        if new_attestations:
                            changed = True
                            found_new_attestations = True
                            logging.info("Got %d new attestation(s) from %s" % (len(new_attestations), calendar_url))
                            for new_att in new_attestations:
                                logging.debug("    %r" % new_att)
                            existing_attestations.update(new_attestations)

                            # FIXME: need to think about DoS attacks here
                            args.cache.merge(upgraded_stamp)
                            sub_stamp.merge(upgraded_stamp)

        if not args.wait:
            break

        elif found_new_attestations:
            # We got something new, so loop around immediately to check if
            # we're now complete
            continue

        else:
            # Nothing new, so wait
            logging.info("Timestamp not complete; waiting %d sec before trying again" % args.wait_interval)
            time.sleep(args.wait_interval)

    return changed


def upgrade_command(args):
    for old_stamp_fd in args.files:
        logging.debug("Upgrading %s" % old_stamp_fd.name)

        ctx = StreamDeserializationContext(old_stamp_fd)
        try:
            detached_timestamp = DetachedTimestampFile.deserialize(ctx)

        # IOError's are already handled by argparse
        except DeserializationError as exp:
            logging.error("Invalid timestamp %r: %s" % (old_stamp_fd.name, exp))
            sys.exit(1)

        changed = upgrade_timestamp(detached_timestamp.timestamp, args)

        if changed:
            backup_name = old_stamp_fd.name + '.bak'
            logging.debug("Got new timestamp data; renaming existing timestamp to %r" % backup_name)

            if os.path.exists(backup_name):
                logging.error("Can't backup timestamp: %r already exists" % backup_name)
                sys.exit(1)

            try:
                os.rename(old_stamp_fd.name, backup_name)
            except IOError as exp:
                logging.error("Couldn't backup exiting timestamp, rename failed: %s" % exp)
                sys.exit(1)

            try:
                with open(old_stamp_fd.name, 'xb') as new_stamp_fd:
                    ctx = StreamSerializationContext(new_stamp_fd)
                    detached_timestamp.serialize(ctx)
            except IOError as exp:
                # FIXME: should we try to restore the old file here?
                logging.error("Couldn't upgrade timestamp %s: %s" % (old_stamp_fd.name, exp))
                sys.exit(1)

        if is_timestamp_complete(detached_timestamp.timestamp, args):
            logging.info("Success! Timestamp is complete")
        else:
            logging.info("Failed; timestamp is not complete")
            sys.exit(1)


def verify_timestamp(timestamp, args):
    args.calendar_urls = []
    upgrade_timestamp(timestamp, args)

    good = False
    for msg, attestation in timestamp.all_attestations():
        if attestation.__class__ == PendingAttestation:
            # Handled by the upgrade_timestamp() call above.
            pass

        elif attestation.__class__ == BitcoinBlockHeaderAttestation:
            if not args.use_bitcoin:
                logging.info("Not checking Bitcoin attestation; disabled")
                continue

            proxy = args.setup_bitcoin()

            try:
                blockhash = proxy.getblockhash(attestation.height)
            except IndexError:
                logging.error("Can't find Bitcoin block! Height %d" % attestation.height)
                continue
            except ConnectionError as exp:
                logging.error("Could not connect to local Bitcoin node: %s" % exp)
                continue

            block_header = proxy.getblockheader(blockhash)

            logging.debug("Attestation block hash: %s" % b2lx(blockhash))

            try:
                attested_time = attestation.verify_against_blockheader(msg, block_header)
            except VerificationError as err:
                logging.error("Bitcoin verification failed: %s" % str(err))
                continue

            logging.debug("Attested time: %d", attested_time)
            logging.info("Success! Bitcoin blockchain attests data existed prior to %s" %
                         datetime.datetime.fromtimestamp(attested_time).isoformat(' '))
            good = True

    return good


def verify_command(args):
    ctx = StreamDeserializationContext(args.timestamp_fd)
    try:
        detached_timestamp = DetachedTimestampFile.deserialize(ctx)
    except DeserializationError as exp:
        logging.error("Invalid timestamp %r: %s" % (args.timestamp_fd.name, exp))
        sys.exit(1)

    if args.hex_digest is not None:
        try:
            digest = binascii.unhexlify(args.hex_digest.encode('utf8'))
        except ValueError:
            args.parser.error('Digest must be hexidecimal')

        if not digest == detached_timestamp.file_digest:
            logging.error("Digest provided does not match digest in timestamp, %s (%s)" %
                          (b2x(detached_timestamp.file_digest), detached_timestamp.file_hash_op_class.TAG_NAME))
            sys.exit(1)

    else:
        if args.target_fd is None:
            # Target not specified, so assume it's the same name as the
            # timestamp file minus the .ots extension.
            if not args.timestamp_fd.name.endswith('.ots'):
                args.parser.error('Timestamp filename does not end in .ots')

            target_filename = args.timestamp_fd.name[:-4]
            logging.info("Assuming target filename is %r" % target_filename)

            args.target_fd = open(target_filename, 'rb')

        logging.debug("Hashing file, algorithm %s" % detached_timestamp.file_hash_op.TAG_NAME)
        actual_file_digest = detached_timestamp.file_hash_op.hash_fd(args.target_fd)
        logging.debug("Got digest %s" % b2x(actual_file_digest))

        if actual_file_digest != detached_timestamp.file_digest:
            logging.debug("Expected digest %s" % b2x(detached_timestamp.file_digest))
            logging.error("File does not match original!")
            sys.exit(1)

    if not verify_timestamp(detached_timestamp.timestamp, args):
        sys.exit(1)


def info_command(args):
    ctx = StreamDeserializationContext(args.file)
    try:
        detached_timestamp = DetachedTimestampFile.deserialize(ctx)
    except DeserializationError as exp:
        logging.error("Invalid timestamp %r: %s" % (args.file.name, exp))
        sys.exit(1)

    print("File %s hash: %s" % (detached_timestamp.file_hash_op.HASHLIB_NAME, hexlify(detached_timestamp.file_digest).decode('utf8')))

    print("Timestamp:")
    print(detached_timestamp.timestamp.str_tree())



def git_extract_command(args):
    import git
    from otsclient.git import hash_signed_commit, deserialize_ascii_armored_timestamp, extract_sig_from_git_commit
    from opentimestamps.git import GitTreeTimestamper

    repo = git.Repo()

    commit = repo.commit(args.commit)
    serialized_signed_commit = commit.data_stream[3].read()

    git_commit, gpg_sig = extract_sig_from_git_commit(serialized_signed_commit)

    if not gpg_sig:
        logging.error("%s is not signed" % args.commit)
        sys.exit(1)

    commit_stamp = deserialize_ascii_armored_timestamp(git_commit, gpg_sig)

    if commit_stamp is None:
        logging.error("%s is signed, but not timestamped" % args.commit)
        sys.exit(1)

    stamper = GitTreeTimestamper(commit.tree)

    try:
        file_stamp = stamper[args.path]
    except Exception as exp:
        # FIXME
        logging.error("%r", exp)
        sys.exit(1)

    # Merge the two timestamps
    append_commit_stamp = stamper.timestamp.ops.add(OpPrepend(commit_stamp.msg))
    append_commit_stamp.merge(tuple(commit_stamp.ops.values())[0])

    if args.timestamp_file is None:
        args.timestamp_file = open(args.path + '.ots', 'wb')

    with args.timestamp_file as fd:
        ctx = StreamSerializationContext(fd)
        file_stamp.serialize(ctx)
