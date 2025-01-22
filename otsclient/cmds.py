# Copyright (C) 2016-2018 The OpenTimestamps developers
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
import io
import logging
import os
import time
import urllib.request
import threading
import bitcoin
import bitcoin.rpc
from queue import Queue, Empty

from bitcoin.core import b2x, b2lx, lx, CTxOut, CTransaction
from bitcoin.core.script import CScript, OP_RETURN

from binascii import hexlify

from opentimestamps.core.notary import *
from opentimestamps.core.timestamp import *
from opentimestamps.core.op import *
from opentimestamps.core.serialize import *
from opentimestamps.timestamp import *
from opentimestamps.bitcoin import *

import opentimestamps.calendar

import otsclient

def remote_calendar(calendar_uri):
    """Create a remote calendar with User-Agent set appropriately"""
    return opentimestamps.calendar.RemoteCalendar(calendar_uri,
                                                  user_agent="OpenTimestamps-Client/%s" % otsclient.__version__)


def create_timestamp(timestamp, calendar_urls, args):
    """Create a timestamp

    calendar_urls - List of calendar's to use
    setup_bitcoin - False if Bitcoin timestamp not desired; set to
                    args.setup_bitcoin() otherwise.
    """

    setup_bitcoin = args.setup_bitcoin if args.use_btc_wallet else False
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

        r = proxy.getblockheader(blockhash, True)
        blockheight = r['height']

        # We have a block hash! We can now generate the attestation from the block.
        block_timestamp = make_timestamp_from_block(timestamp.msg, block, blockheight)
        assert block_timestamp is not None
        timestamp.merge(block_timestamp)

    m = args.m
    n = len(calendar_urls)
    if m > n or m <= 0:
        logging.error("m (%d) cannot be greater than available calendar%s (%d) neither less or equal 0" % (m,  "" if n == 1 else "s", n))
        sys.exit(1)

    logging.debug("Doing %d-of-%d request, timeout is %d second%s" % (m, n, args.timeout, "" if n == 1 else "s"))

    q = Queue()
    for calendar_url in calendar_urls:
        submit_async(calendar_url, timestamp.msg, q, args.timeout)

    start = time.time()
    merged = 0
    for i in range(n):
        try:
            remaining = max(0, args.timeout - (time.time() - start))
            result = q.get(block=True, timeout=remaining)
            try:
                if isinstance(result, Timestamp):
                    timestamp.merge(result)
                    merged += 1
                else:
                    logging.debug(str(result))
            except Exception as error:
                logging.debug(str(error))

        except Empty:
            # Timeout
            continue

    if merged < m:
        logging.error("Failed to create timestamp: need at least %d attestation%s but received %s within timeout" % (m, "" if m == 1 else "s", merged))
        sys.exit(1)
    logging.debug("%.2f seconds elapsed" % (time.time()-start))


def submit_async(calendar_url, msg, q, timeout):

    def submit_async_thread(remote, msg, q, timeout):
        try:
            calendar_timestamp = remote.submit(msg, timeout=timeout)
            q.put(calendar_timestamp)
        except Exception as exc:
            q.put(exc)

    logging.info('Submitting to remote calendar %s' % calendar_url)
    remote = remote_calendar(calendar_url)
    t = threading.Thread(target=submit_async_thread, args=(remote, msg, q, timeout))
    t.start()


def stamp_command(args):
    # Create initial commitment ops for all files
    file_timestamps = []
    merkle_roots = []
    if not args.files:
        args.files = [sys.stdin.buffer]

    for fd in args.files:
        try:
            file_timestamp = DetachedTimestampFile.from_fd(OpSHA256(), fd)
        except OSError as exp:
            # Most IO errors such as a missing file or bad permissions are
            # caught by argparse; we'll only get to this point if we can open
            # the file, yet there's still an IO error reading the contents of
            # it, which is a tricky thing to test.
            #
            # A neat trick is to try to timestamp a /proc/<pid>/mem file that
            # you have permissions for. On Linux at least, actually reading the
            # contents of these files is still not allowed, as you need the
            # correct magic sysctls or something, which gives us a nice OSError
            # to test with.
            logging.error("Could not read %r: %s" % (fd.name, exp))
            sys.exit(1)

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
        # Neither calendar nor wallet specified; add defaults
        args.calendar_urls.append('https://a.pool.opentimestamps.org')
        args.calendar_urls.append('https://b.pool.opentimestamps.org')
        args.calendar_urls.append('https://a.pool.eternitywall.com')
        args.calendar_urls.append('https://ots.btc.catallaxy.com')

    create_timestamp(merkle_tip, args.calendar_urls, args)

    if args.wait:
        upgrade_timestamp(merkle_tip, args)
        logging.info("Timestamp complete; saving")

    for (in_file, file_timestamp) in zip(args.files, file_timestamps):
        timestamp_file_path = in_file.name + '.ots'
        special_output_fd = None
        if in_file == sys.stdin.buffer:
            special_output_fd = sys.stdout.buffer

        try:
            with special_output_fd or open(timestamp_file_path, 'xb') as timestamp_fd:
                ctx = StreamSerializationContext(timestamp_fd)
                file_timestamp.serialize(ctx)

                # pass --nowatch to skip
                if not args.nowatch:
                    # add this timestamp to the watchlist
                    args.cache.watch(os.path.abspath(timestamp_file_path))
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

    if not hasattr(args, "runtime_cache"):
        args.runtime_cache = {}

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
            commitment = sub_stamp.msg

            # If the runtime cache already indicates that calendar servers have
            # been checked and there are no mature timestamps available, then
            # don't check the servers a second time during this run.
            if b2x(commitment) in args.runtime_cache.keys() and args.runtime_cache[b2x(commitment)] == False:
                logging.info("Runtime cache indicates timestamp not complete")
                continue

            for attestation in sub_stamp.attestations:
                if attestation.__class__ == PendingAttestation:
                    calendar_urls = args.calendar_urls
                    if calendar_urls:
                        # FIXME: this message is incorrectly displayed, disabling for now.
                        #
                        # logging.debug("Attestation URI %s overridden by user-specified remote calendar(s)" % attestation.uri)
                        pass
                    else:
                        if attestation.uri in args.whitelist:
                            calendar_urls = [attestation.uri]
                        else:
                            logging.warning("Ignoring attestation from calendar %s: Calendar not in whitelist" % attestation.uri)
                            continue

                    for calendar_url in calendar_urls:
                        logging.debug("Checking calendar %s for %s" % (attestation.uri, b2x(commitment)))
                        calendar = remote_calendar(calendar_url)

                        try:
                            upgraded_stamp = calendar.get_timestamp(commitment)
                        except opentimestamps.calendar.CommitmentNotFoundError as exp:
                            logging.warning("Calendar %s: %s" % (attestation.uri, exp.reason))
                            continue
                        except urllib.error.URLError as exp:
                            logging.warning("Calendar %s: %s" % (attestation.uri, exp.reason))
                            continue

                        atts_from_remote = get_attestations(upgraded_stamp)
                        if atts_from_remote:
                            logging.info("Got %d attestation(s) from %s" % (len(atts_from_remote), calendar_url))
                            for att in get_attestations(upgraded_stamp):
                                logging.debug("    %r" % att)

                        new_attestations = get_attestations(upgraded_stamp).difference(existing_attestations)
                        if new_attestations:
                            changed = True
                            found_new_attestations = True
                            existing_attestations.update(new_attestations)

                            # FIXME: need to think about DoS attacks here
                            args.cache.merge(upgraded_stamp)
                            sub_stamp.merge(upgraded_stamp)

                    if changed == False:
                        # commitment not timestamped in any of the calendars
                        args.runtime_cache[b2x(commitment)] = False

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

    # defer certain sys.exit(1) calls until later
    error = False

    completed_timestamps = []

    # Timestamp commitment cache that exists only during active processing.
    # Don't check calendar servers multiple times for the same commitment.
    args.runtime_cache = {}

    for old_stamp_fd in args.files:
        # Bypass file descriptor limit by opening a file one at a time when a
        # filepath is given instead of a file descriptor.
        if isinstance(old_stamp_fd, str):
            filepath = old_stamp_fd
            try:
                old_stamp_fd = open(filepath, "rb")
                logging.info("Upgrading %s" % filepath)
            except FileNotFoundError:
                logging.error("Error! Failed to open file %r" % filepath)
                error = True
                continue
        else:
            logging.debug("Upgrading %s" % old_stamp_fd.name)

        ctx = StreamDeserializationContext(old_stamp_fd)
        try:
            detached_timestamp = DetachedTimestampFile.deserialize(ctx)
            old_stamp_fd.close()

        # IOError's are already handled by argparse
        except BadMagicError:
            logging.error("Error! %r is not a timestamp file" % old_stamp_fd.name)
            error = True
            continue
        except DeserializationError as exp:
            logging.error("Invalid timestamp file %r: %s" % (old_stamp_fd.name, exp))
            error = True
            continue

        changed = upgrade_timestamp(detached_timestamp.timestamp, args)

        if changed and not args.dry_run:
            backup_name = old_stamp_fd.name + '.bak'
            logging.debug("Got new timestamp data; renaming existing timestamp to %r" % backup_name)

            if os.path.exists(backup_name):
                logging.error("Could not backup timestamp: %r already exists" % backup_name)
                error = True
                continue

            try:
                os.rename(old_stamp_fd.name, backup_name)
            except IOError as exp:
                logging.error("Could not backup timestamp: %s" % exp)
                error = True
                continue

            try:
                with open(old_stamp_fd.name, 'xb') as new_stamp_fd:
                    ctx = StreamSerializationContext(new_stamp_fd)
                    detached_timestamp.serialize(ctx)
            except IOError as exp:
                # FIXME: should we try to restore the old file here?
                logging.error("Could not upgrade timestamp %s: %s" % (old_stamp_fd.name, exp))
                error = True
                continue

        if is_timestamp_complete(detached_timestamp.timestamp, args):
            logging.info("Success! Timestamp complete")
            completed_timestamps.append(os.path.abspath(old_stamp_fd.name))
        else:
            logging.warning("Failed! Timestamp not complete")
            error = True
            continue

    # remove old entries from the watchlist
    if not args.dry_run:
        old_watchlist = args.cache.watchlist()
        args.cache.unwatch(old_watchlist, completed_timestamps)

    if error:
        logging.error("Encountered an earlier error. Exiting.")
        sys.exit(1)


def upgradewatchlist_command(args):
    args.files = [filename for filename in args.cache.watchlist() if filename != ""]
    return upgrade_command(args)

def verify_timestamp(timestamp, args):
    args.calendar_urls = []
    upgrade_timestamp(timestamp, args)

    def attestation_key(item):
        (msg, attestation) = item
        if attestation.__class__ == BitcoinBlockHeaderAttestation:
            return attestation.height
        else:
            return 2**32-1

    good = False
    for msg, attestation in sorted(timestamp.all_attestations(), key=attestation_key):
        if attestation.__class__ == PendingAttestation:
            # Handled by the upgrade_timestamp() call above.
            pass

        elif attestation.__class__ == BitcoinBlockHeaderAttestation:
            if not args.use_bitcoin:
                logging.warning("Not checking Bitcoin attestation; Bitcoin disabled")
                logging.info("To verify manually, check that Bitcoin block %d has merkleroot %s" %
                                (attestation.height, b2lx(msg)))
                continue

            proxy = args.setup_bitcoin()

            try:
                block_count = proxy.getblockcount()
                blockhash = proxy.getblockhash(attestation.height)
            except IndexError:
                logging.error("Bitcoin block height %d not found; %d is highest known block" % (attestation.height, block_count))
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

            logging.info("Success! Bitcoin block %d attests existence as of %s" %
                            (attestation.height,
                             time.strftime('%Y-%m-%d %Z',
                                          time.localtime(attested_time))))
            good = True

            # One Bitcoin attestation is enough
            break

    return good


def verify_command(args):
    ctx = StreamDeserializationContext(args.timestamp_fd)
    try:
        detached_timestamp = DetachedTimestampFile.deserialize(ctx)
    except BadMagicError:
        logging.error("Error! %r is not a timestamp file." % args.timestamp_fd.name)
        sys.exit(1)
    except DeserializationError as exp:
        logging.error("Invalid timestamp file %r: %s" % (args.timestamp_fd.name, exp))
        sys.exit(1)

    if args.hex_digest is not None:
        try:
            digest = binascii.unhexlify(args.hex_digest.encode('utf8'))
        except ValueError:
            args.parser.error('Digest must be hexadecimal')

        if not digest == detached_timestamp.file_digest:
            logging.error("Digest provided does not match digest in timestamp, %s (%s)" %
                          (b2x(detached_timestamp.file_digest), detached_timestamp.file_hash_op.TAG_NAME))
            sys.exit(1)

    else:
        if args.target_fd is None:
            # Target not specified, so assume it's the same name as the
            # timestamp file minus the .ots extension.
            if not args.timestamp_fd.name.endswith('.ots'):
                args.parser.error('Timestamp filename does not end in .ots')

            target_filename = args.timestamp_fd.name[:-4]
            logging.info("Assuming target filename is %r" % target_filename)

            try:
                args.target_fd = open(target_filename, 'rb')
            except IOError as exp:
                logging.error('Could not open target: %s' % exp)
                sys.exit(1)

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
    except BadMagicError:
        logging.error("Error! %r is not a timestamp file." % args.file.name)
        sys.exit(1)
    except DeserializationError as exp:
        logging.error("Invalid timestamp file %r: %s" % (args.file.name, exp))
        sys.exit(1)

    print("File %s hash: %s" % (detached_timestamp.file_hash_op.HASHLIB_NAME, hexlify(detached_timestamp.file_digest).decode('utf8')))

    print("Timestamp:")
    print(detached_timestamp.timestamp.str_tree(verbosity=args.verbosity))


def verify_all_attestations(timestamp, attestations_to_verify, args):
    for msg, attestation in timestamp.all_attestations():
        if attestation.__class__ in attestations_to_verify:
            # as of now, only bitcoin attestations can be verified
            if attestation.__class__ == BitcoinBlockHeaderAttestation:
                if not args.use_bitcoin:
                    logging.error("Bitcoin disabled, could not check attestations")
                    sys.exit(1)

                proxy = args.setup_bitcoin()

                try:
                    block_count = proxy.getblockcount()
                    blockhash = proxy.getblockhash(attestation.height)
                    block_header = proxy.getblockheader(blockhash)
                    attested_time = attestation.verify_against_blockheader(msg, block_header)
                except IndexError:
                    logging.error("Bitcoin block height %d not found; %d is highest known block" % (
                        attestation.height, block_count))
                    sys.exit(1)
                except ConnectionError as exp:
                    logging.error("Could not connect to local Bitcoin node: %s" % exp)
                    sys.exit(1)
                except VerificationError as err:
                    logging.error("Bitcoin verification failed: %s" % str(err))
                    sys.exit(1)

            else:
                logging.error("Could not verify; verification with %s not supported" % str(attestation.__class__))
                sys.exit(1)


def discard_attestations(timestamp, attestations_to_discard):
    for a in timestamp.attestations.copy():
        # The client should be able to discard pending attestations from a specified calendar,
        # thus pending attestations are managed differently
        if a.__class__ == PendingAttestation:
            if PendingAttestation in attestations_to_discard:
                timestamp.attestations.remove(a)
            elif a in attestations_to_discard:
                timestamp.attestations.remove(a)
        elif a.__class__ in attestations_to_discard:
            timestamp.attestations.remove(a)

    for op, stamp in timestamp.ops.items():
        discard_attestations(stamp, attestations_to_discard)


def discard_suboptimal(timestamp, target_attestation):
    opt_att = None
    opt_nod = None
    opt_dep = 0
    # optimal attestation, node and depth;
    # it is necessary to store the optimal node to go back and remove an updated optimal attestation.

    for op, stamp in timestamp.ops.items():
        cur_opt_att, cur_opt_nod, cur_opt_dep = discard_suboptimal(stamp, target_attestation)
        cur_opt_dep += 1 + (0 if len(op) == 0 else len(op[0]))
        # all Op are encoded with one byte;
        # depth does not count attestation sizes, although they may be relevant for overall size.
        if cur_opt_att:
            if not opt_att:
                opt_att, opt_nod, opt_dep = cur_opt_att, cur_opt_nod, cur_opt_dep
            elif cur_opt_att > opt_att:
                cur_opt_nod.attestations.remove(cur_opt_att)
            elif cur_opt_att < opt_att:
                opt_nod.attestations.remove(opt_att)
                opt_att, opt_nod, opt_dep = cur_opt_att, cur_opt_nod, cur_opt_dep
            else:
                # attestations are equal, check depth
                if cur_opt_dep < opt_dep:
                    opt_nod.attestations.remove(opt_att)
                    opt_att, opt_nod, opt_dep = cur_opt_att, cur_opt_nod, cur_opt_dep
                else:
                    cur_opt_nod.attestations.remove(cur_opt_att)

    for a in timestamp.attestations.copy():
        if a.__class__ == target_attestation:
            if not opt_att:
                opt_att, opt_nod = a, timestamp
            else:
                if a > opt_att:
                    timestamp.attestations.remove(a)
                else:
                    # if a == opt_att, then a is optimal, because the timestamp attestation is less deep
                    opt_nod.attestations.remove(opt_att)
                    opt_att, opt_nod = a, timestamp

    return opt_att, opt_nod, opt_dep


def prune_tree(timestamp):
    prunable = len(timestamp.attestations) == 0
    changed = False

    for op, stamp in timestamp.ops.copy().items():
        stamp_prunable, stamp_changed = prune_tree(stamp)
        changed = changed or stamp_changed or stamp_prunable
        if stamp_prunable:
            del timestamp.ops[op]
        else:
            prunable = False

    return prunable, changed


def prune_timestamp(timestamp, attestations_to_verify, attestations_to_discard, args):
    """Attempt to prune timestamp

    Returns prunable and changed:
    - prunable is True iff the pruned timestamp is empty;
    - changed is True iff the pruned timestamp differs from the one input.

    Note that it is inefficient to explore the tree several (5) times, but it avoids errors in particular cases.
    If the requests are more specific (e.g. discard all attestations except best "btc"), then more efficient
    implementation could be made.
    """

    verify_all_attestations(timestamp, attestations_to_verify, args)
    discard_attestations(timestamp, attestations_to_discard)
    # discard suboptimal attestations for each comparable attestation class
    discard_suboptimal(timestamp, BitcoinBlockHeaderAttestation)
    discard_suboptimal(timestamp, LitecoinBlockHeaderAttestation)
    prunable, changed = prune_tree(timestamp)
    return prunable, changed


def prune_command(args):
    ctx = StreamDeserializationContext(args.timestamp_fd)
    try:
        detached_timestamp = DetachedTimestampFile.deserialize(ctx)
    except BadMagicError:
        logging.error("Error! %r is not a timestamp file." % args.timestamp_fd.name)
        sys.exit(1)
    except DeserializationError as exp:
        logging.error("Invalid timestamp file %r: %s" % (args.timestamp_fd.name, exp))
        sys.exit(1)

    attestations_to_verify = []
    if args.attestations_to_verify:
        for s in args.attestations_to_verify:
            if s == "btc":
                attestations_to_verify += [BitcoinBlockHeaderAttestation]
            else:
                args.parser.error("argument --verify: invalid choice: '%s' (choose from 'btc')" % s)
                sys.exit(1)
    elif not args.no_verify:
        # default case, otherwise attestations_to_verify is left empty
        attestations_to_verify = [BitcoinBlockHeaderAttestation]

    attestations_to_discard = []
    if args.attestations_to_discard:
        for s in args.attestations_to_discard:
            if s == "btc":
                attestations_to_discard += [BitcoinBlockHeaderAttestation]
            elif s == "ltc":
                attestations_to_discard += [LitecoinBlockHeaderAttestation]
            elif s == "unknown":
                attestations_to_discard += [UnknownAttestation]
            elif s[:8] == "pending:":
                if s[8:] == "*":
                    attestations_to_discard += [PendingAttestation]
                else:
                    attestations_to_discard += [PendingAttestation(s[8:])]
            else:
                args.parser.error("argument --discard: invalid choice: '%s' (choose from 'btc', 'ltc', 'unknown', "
                                  "'pending:*', 'pending:uri')" % s)
                sys.exit(1)
    else:
        # default case
        attestations_to_discard = [PendingAttestation]

    empty, changed = prune_timestamp(detached_timestamp.timestamp, attestations_to_verify, attestations_to_discard, args)

    if empty:
        logging.warning("Failed! All attestations have been discarded")
        sys.exit(1)
    elif not changed:
        logging.warning("Failed! Nothing has been discarded")
        sys.exit(1)
    else:
        backup_name = args.timestamp_fd.name + ".bak"
        logging.debug("Prune successful; renaming existing timestamp to %r" % backup_name)
        if os.path.exists(backup_name):
            logging.error("Could not backup timestamp: %r already exists" % backup_name)
            sys.exit(1)
        try:
            os.rename(args.timestamp_fd.name, backup_name)
        except IOError as exp:
            logging.error("Could not backup timestamp: %s" % exp)
            sys.exit(1)

        try:
            with open(args.timestamp_fd.name, 'xb') as new_stamp_fd:
                ctx = StreamSerializationContext(new_stamp_fd)
                detached_timestamp.serialize(ctx)
        except IOError as exp:
            # FIXME: should we try to restore the old file here?
            logging.error("Could not upgrade timestamp %s: %s" % (args.timestamp_fd.name, exp))
            sys.exit(1)

        logging.info("Success! Timestamp pruned")


def git_extract_command(args):
    import git
    from otsclient.git import deserialize_ascii_armored_timestamp, extract_sig_from_git_commit
    from opentimestamps.core.git import GitTreeTimestamper

    repo = git.Repo(search_parent_directories=True)
    repo_base_path = repo.working_tree_dir

    commit = repo.commit(args.commit)
    serialized_signed_commit = commit.data_stream[3].read()

    git_commit, gpg_sig = extract_sig_from_git_commit(serialized_signed_commit)

    if not gpg_sig:
        logging.error("%s is not signed" % args.commit)
        sys.exit(1)

    (major_version, minor_version, commit_stamp) = deserialize_ascii_armored_timestamp(git_commit, gpg_sig)

    if commit_stamp is None:
        logging.error("%s is signed, but not timestamped" % args.commit)
        sys.exit(1)

    elif minor_version != 1:
        logging.error("Commit was timestamped, but --rehash-trees was not used; can't extract per-file timestamp.")
        sys.exit(1)


    stamper = GitTreeTimestamper(commit.tree)

    # args.path is relative to the CWD, but for git we need a path relative to
    # the repo base.
    #
    # FIXME: Does this work with bare repos?
    # FIXME: Does this always work when the user has specified a different
    # commit than HEAD?
    git_tree_path = os.path.relpath(args.path, start=repo_base_path)

    if git_tree_path.startswith('..'):
        logging.error("%r is outside repository" % args.path)
        sys.exit(1)

    try:
        file_stamp = stamper[git_tree_path]

    # FIXME: better if these were ots-git-specific exceptions
    except (FileNotFoundError, ValueError) as exp:
        logging.error("%s", exp)
        sys.exit(1)

    blob = commit.tree[git_tree_path]
    if args.annex and blob.mode == 0o120000:
        fd = io.BytesIO()
        blob.stream_data(fd)
        link_contents = fd.getvalue()

        if b'SHA256' in link_contents:
            hex_digest_start = link_contents.find(b'--')
            if hex_digest_start < 0:
                logging.error("%r not a git-annex symlink" % args.path)
                sys.exit(1)
            hex_digest_start += 2

            hex_digest = link_contents[hex_digest_start:hex_digest_start+32*2]

            new_file_stamp = DetachedTimestampFile(OpSHA256(), Timestamp(binascii.unhexlify(hex_digest)))

            new_file_stamp.timestamp.ops.add(OpHexlify()) \
                                    .ops.add(OpPrepend(link_contents[0:hex_digest_start])) \
                                    .ops.add(OpAppend(link_contents[hex_digest_start+32*2:])) \
                                    .ops[OpSHA256()] = file_stamp.timestamp

            file_stamp = new_file_stamp

        else:
            logging.error("%r not a SHA256 git-annex symlink" % args.path)
            sys.exit(1)


    elif blob.mode == 0o120000:
        logging.error("%r is a symlink; see --annex" % args.path)
        sys.exit(1)

    # Merge the two timestamps

    # First, we need to find the tip of the file timestamp
    tip = file_stamp.timestamp
    while tip.ops:
        assert len(tip.ops) == 1 # FIXME: should handle divergence
        tip = tuple(tip.ops.values())[0]

    # Second, splice it to the commit timestamp.
    #
    # Remember that the commit timestamp was on SHA256(SHA256(git_commit) +
    # SHA256(gpg_sig)), and the commitment to the tree is in the first op - an
    # OpAppend - so we have to create an OpPrepend:
    append_commit_stamp = tip.ops.add(OpPrepend(commit_stamp.msg))
    append_commit_stamp.merge(tuple(commit_stamp.ops.values())[0])

    timestamp_file_path = None
    try:
        if args.timestamp_file is None:
            timestamp_file_path = args.path + '.ots'
            args.timestamp_file = open(timestamp_file_path, 'xb')

        else:
            timestamp_file_path = args.timestamp_file.name

        with args.timestamp_file as fd:
            ctx = StreamSerializationContext(fd)
            file_stamp.serialize(ctx)

    except IOError as exp:
        logging.error("Failed to create timestamp %r: %s" % (timestamp_file_path, exp))
        sys.exit(1)
