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

import appdirs
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
import otsclient.headers

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

                    commitment = sub_stamp.msg
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
            old_stamp_fd.close()

        # IOError's are already handled by argparse
        except BadMagicError:
            logging.error("Error! %r is not a timestamp file" % old_stamp_fd.name)
            sys.exit(1)
        except DeserializationError as exp:
            logging.error("Invalid timestamp file %r: %s" % (old_stamp_fd.name, exp))
            sys.exit(1)

        changed = upgrade_timestamp(detached_timestamp.timestamp, args)

        if changed and not args.dry_run:
            backup_name = old_stamp_fd.name + '.bak'
            logging.debug("Got new timestamp data; renaming existing timestamp to %r" % backup_name)

            if os.path.exists(backup_name):
                logging.error("Could not backup timestamp: %r already exists" % backup_name)
                sys.exit(1)

            try:
                os.rename(old_stamp_fd.name, backup_name)
            except IOError as exp:
                logging.error("Could not backup timestamp: %s" % exp)
                sys.exit(1)

            try:
                with open(old_stamp_fd.name, 'xb') as new_stamp_fd:
                    ctx = StreamSerializationContext(new_stamp_fd)
                    detached_timestamp.serialize(ctx)
            except IOError as exp:
                # FIXME: should we try to restore the old file here?
                logging.error("Could not upgrade timestamp %s: %s" % (old_stamp_fd.name, exp))
                sys.exit(1)

        if is_timestamp_complete(detached_timestamp.timestamp, args):
            logging.info("Success! Timestamp complete")
        else:
            logging.warning("Failed! Timestamp not complete")
            sys.exit(1)


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

            header_source = args.get_header_source()

            try:
                block_header = header_source.get_header_at_height(attestation.height)
            except IndexError as exp:
                logging.error("%s" % exp)
                continue
            except ConnectionError as exp:
                logging.error("Could not connect to header source: %s" % exp)
                continue

            logging.debug("Attestation block hash: %s" % b2lx(block_header.GetHash()))

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

                header_source = args.get_header_source()

                try:
                    block_header = header_source.get_header_at_height(attestation.height)
                    attested_time = attestation.verify_against_blockheader(msg, block_header)
                except IndexError as exp:
                    logging.error("%s" % exp)
                    sys.exit(1)
                except ConnectionError as exp:
                    logging.error("Could not connect to header source: %s" % exp)
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


def headers_fetch_command(args):
    """Fetch Bitcoin block headers into a local archive.

    Two transports are supported. The HTTP fetcher (default) queries
    Esplora-compatible block explorers; it's well-suited for small ranges
    around a specific OTS attestation, with cross-source quorum agreement.
    The P2P fetcher (--p2p, --p2p-peer) talks Bitcoin's native getheaders
    protocol; it returns up to 2000 headers per round trip and is the
    right choice for bulk fetches like populating from genesis.
    """
    if args.headers_path is None:
        # Default is network-suffixed so mainnet/testnet archives don't
        # collide on the same default path. Lives in the OS cache dir
        # regardless of --no-cache (which only disables the timestamp
        # cache).
        appdirs_default = appdirs.AppDirs('ots', 'opentimestamps')
        args.headers_path = os.path.join(
            appdirs_default.user_cache_dir, 'headers-%s.bin' % args.btc_net)

    archive = otsclient.headers.HeaderArchive(args.headers_path)

    use_p2p = args.use_p2p or bool(args.p2p_peers)
    if use_p2p and args.source_urls:
        logging.error("--p2p and --source are mutually exclusive")
        sys.exit(1)

    # If the archive does not exist yet, create it. If it does exist,
    # the network and start_height are already fixed and we just append.
    if not archive.exists():
        start_height = args.since_height if args.since_height is not None else 0
        try:
            archive.create(args.btc_net, start_height)
            logging.info("Created header archive %s (network=%s, start_height=%d)" % (
                args.headers_path, args.btc_net, start_height))
        except otsclient.headers.HeaderArchiveError as exp:
            logging.error("Could not create archive: %s" % exp)
            sys.exit(1)

    try:
        archive_network, start_height, header_count = archive.read_file_header()
    except otsclient.headers.HeaderArchiveError as exp:
        logging.error("Invalid archive: %s" % exp)
        sys.exit(1)

    if archive_network != args.btc_net:
        logging.error("Archive network %r does not match selected network %r" % (
            archive_network, args.btc_net))
        sys.exit(1)

    if use_p2p:
        _headers_fetch_p2p(args, archive)
        return

    # Resolve fetch sources
    if args.source_urls:
        sources = [otsclient.headers.EsploraHeaderFetcher(url) for url in args.source_urls]
    else:
        sources = otsclient.headers.make_default_esplora_sources(args.btc_net)
        if not sources:
            logging.error("No default fetch sources for network %r; provide --source URL(s)" %
                          args.btc_net)
            sys.exit(1)

    fetcher = otsclient.headers.HeaderFetcher(sources, quorum=args.quorum)

    # Resolve since_height: the next height to fetch.
    next_height = start_height + header_count
    if args.since_height is not None and args.since_height != next_height:
        if args.since_height < next_height:
            logging.info("Skipping --since-height %d; archive already has up to height %d" % (
                args.since_height, next_height - 1))
        else:
            logging.error(
                "Cannot fetch from height %d: archive ends at %d and headers must be appended in order" % (
                    args.since_height, next_height - 1))
            sys.exit(1)

    # Resolve until_height. If not given, query sources for current chain tip
    # and pick the median (resilient to a single source reporting a stale
    # or future tip).
    if args.until_height is None:
        tip_heights = []
        for source in sources:
            try:
                tip_heights.append(source.get_tip_height())
            except Exception as exp:
                logging.debug("Source %r failed tip lookup: %s" % (source.base_url, exp))
        if not tip_heights:
            logging.error("Could not determine chain tip from any source; "
                          "use --until-height to specify explicitly")
            sys.exit(1)
        tip_heights.sort()
        until_height = tip_heights[len(tip_heights) // 2]
        logging.info("Auto-detected chain tip height %d (from %d source(s))" % (
            until_height, len(tip_heights)))
    else:
        until_height = args.until_height

    if until_height < next_height:
        logging.info("Nothing to do: archive already covers up to height %d" % (next_height - 1))
        return

    logging.info("Fetching headers %d..%d from %d source(s), quorum=%d" % (
        next_height, until_height, len(sources), fetcher.quorum))

    fetched = 0
    log_every = 100
    for height in range(next_height, until_height + 1):
        try:
            header = fetcher.fetch_header(height)
            archive.append_header(header)
            fetched += 1
        except (otsclient.headers.HeaderArchiveError, ConnectionError) as exp:
            logging.error("Stopping at height %d: %s" % (height, exp))
            sys.exit(1)

        if fetched % log_every == 0:
            logging.info("... fetched %d headers (at height %d)" % (fetched, height))

    logging.info("Done. Fetched %d header(s); archive now covers %d..%d" % (
        fetched, start_height, until_height))


def _parse_p2p_peer_spec(spec):
    """Parse a 'host' or 'host:port' string into a (host, port) tuple.

    Defaults to the network's default port if no port is given.
    """
    if ':' in spec:
        host, port_str = spec.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError("Invalid port in peer spec %r" % spec)
    else:
        host = spec
        port = bitcoin.params.DEFAULT_PORT
    return (host, port)


def _headers_fetch_p2p(args, archive):
    """Fetch headers via Bitcoin P2P getheaders."""
    if args.p2p_peers:
        try:
            peers = [_parse_p2p_peer_spec(s) for s in args.p2p_peers]
        except ValueError as exp:
            logging.error("%s" % exp)
            sys.exit(1)
    else:
        peers = None  # signals DNS-seed discovery

    fetcher = otsclient.headers.BitcoinP2PHeaderFetcher(
        network=args.btc_net,
        peers=peers,
    )

    if args.until_height is not None:
        logging.info("Fetching headers via Bitcoin P2P up to height %d" % args.until_height)
    else:
        logging.info("Fetching headers via Bitcoin P2P to the chain tip")

    try:
        appended = fetcher.fetch_into(archive, until_height=args.until_height)
    except otsclient.headers.P2PFetcherError as exp:
        logging.error("P2P fetch failed: %s" % exp)
        sys.exit(1)

    _network, start_height, header_count = archive.read_file_header()
    end_height = start_height + header_count - 1
    logging.info("Done. Appended %d header(s); archive now covers %d..%d" % (
        appended, start_height, end_height))


def headers_info_command(args):
    """Print information about a local header archive."""
    archive = otsclient.headers.HeaderArchive(args.archive_path)
    if not archive.exists():
        logging.error("Archive file not found: %s" % args.archive_path)
        sys.exit(1)

    try:
        info = archive.info()
    except otsclient.headers.HeaderArchiveError as exp:
        logging.error("Invalid archive: %s" % exp)
        sys.exit(1)

    print("Path:         %s" % info['path'])
    print("Network:      %s" % info['network'])
    print("Header count: %d" % info['header_count'])
    print("Height range: %d..%s" % (
        info['start_height'],
        info['end_height'] if info['end_height'] is not None else '(empty)'))
    print("File size:    %d bytes" % info['file_size'])


def headers_bootstrap_command(args):
    """Download a prebuilt header archive from a URL and install it locally.

    The trust model is identical to an archive built via `ots headers fetch`:
    PoW and prev-hash continuity are validated for every header before the
    file is installed. The source URL doesn't need to be trusted -- the math
    is the trust signal. Useful for grabbing a snapshot from GitHub Releases,
    IPFS, a friend's mirror, etc., without spending the minutes a P2P fetch
    or the hours an HTTP fetch would take.
    """
    if args.headers_path is None:
        appdirs_default = appdirs.AppDirs('ots', 'opentimestamps')
        args.headers_path = os.path.join(
            appdirs_default.user_cache_dir,
            'headers-%s.bin' % args.btc_net)

    if os.path.exists(args.headers_path) and not args.force_overwrite:
        logging.error(
            "Output path already exists: %s\n"
            "Pass --force to overwrite, or pick a different --output path." % (
                args.headers_path))
        sys.exit(1)

    try:
        info = otsclient.headers.bootstrap_archive_from_url(
            url=args.url,
            output_path=args.headers_path,
            network=args.btc_net,
            expected_sha256=args.expected_sha256)
    except otsclient.headers.HeaderArchiveError as exp:
        logging.error("%s" % exp)
        sys.exit(1)

    end_height = (info['start_height'] + info['header_count'] - 1
                  if info['header_count'] > 0 else info['start_height'])
    logging.info("Done. Installed %s (network=%s, headers=%d, heights %d..%d)" % (
        info['path'], info['network'], info['header_count'],
        info['start_height'], end_height))
