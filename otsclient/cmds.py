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

        unfunded_tx = CTransaction([],[CTxOut(0, CScript([OP_RETURN, timestamp.msg]))])
        r = proxy.fundrawtransaction(unfunded_tx) # FIXME: handle errors
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

        logging.info('Submitting to remote calendar %r' % calendar_url)
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

    for (in_file, file_timestamp) in zip(args.files, file_timestamps):
        timestamp_file_path = in_file.name + '.ots'
        with open(timestamp_file_path, 'xb') as timestamp_fd:
            ctx = StreamSerializationContext(timestamp_fd)
            file_timestamp.serialize(ctx)

def upgrade_command(args):
    for old_stamp_fd in args.files:
        logging.debug("Upgrading %s" % old_stamp_fd.name)

        ctx = StreamDeserializationContext(old_stamp_fd)
        detached_timestamp = DetachedTimestampFile.deserialize(ctx)

        def directly_verified(stamp):
            if stamp.attestations:
                yield stamp
            else:
                for result_stamp in stamp.ops.values():
                    yield from directly_verified(result_stamp)
            yield from ()

        upgraded = False
        for sub_stamp in directly_verified(detached_timestamp.timestamp):
            for attestation in sub_stamp.attestations:
                if attestation.__class__ == PendingAttestation:
                    calendar_urls = args.calendar_urls
                    if not calendar_urls:
                        calendar_urls = [attestation.uri]

                    commitment = sub_stamp.msg
                    for calendar_url in calendar_urls:
                        logging.debug("Checking calendar %s for %s" % (attestation.uri, b2x(commitment)))
                        calendar = RemoteCalendar(calendar_url)

                        try:
                            upgraded_stamp = calendar.get_timestamp(commitment)
                        except KeyError:
                            logging.info("Calendar %s: No timestamp found" % attestation.uri)
                            continue

                        sub_stamp.merge(upgraded_stamp)
                        upgraded = True
                        logging.info("Upgraded timestamp with %r" % upgraded_stamp.ops)

        # Rename to save backup
        os.rename(old_stamp_fd.name, old_stamp_fd.name + '.bak')
        with open(old_stamp_fd.name, 'xb') as new_stamp_fd:
            ctx = StreamSerializationContext(new_stamp_fd)
            detached_timestamp.serialize(ctx)

def verify_timestamp(timestamp, args):
    for msg, attestation in timestamp.all_attestations():
        if attestation.__class__ == PendingAttestation:
            logging.info("Pending attestation %s" % attestation.uri)

        elif attestation.__class__ == BitcoinBlockHeaderAttestation:
            proxy = args.setup_bitcoin()

            try:
                blockhash = proxy.getblockhash(attestation.height)
            except IndexError:
                logging.error("Can't find Bitcoin block! Height %d" % attestation.height)
                return False

            block_header = proxy.getblockheader(blockhash)

            logging.debug("Attestation block hash: %s" % b2lx(blockhash))

            try:
                attested_time = attestation.verify_against_blockheader(msg, block_header)
            except VerificationError as err:
                logging.error("Bitcoin verification failed: %s" % str(err))
                return False

            logging.debug("Attested time: %d", attested_time)
            logging.info("Success! Bitcoin blockchain attests data existed prior to %s" % \
                            datetime.datetime.fromtimestamp(attested_time).isoformat(' '))
    return True

def verify_command(args):
    ctx = StreamDeserializationContext(args.timestamp_fd)
    detached_timestamp = DetachedTimestampFile.deserialize(ctx)

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
    detached_timestamp = DetachedTimestampFile.deserialize(ctx)

    print("File %s hash: %s" % (detached_timestamp.file_hash_op.HASHLIB_NAME, hexlify(detached_timestamp.file_digest).decode('utf8')))

    print("Timestamp:")
    print(detached_timestamp.timestamp.str_tree())
