# Copyright (C) 2016 The OpenTimestamps developers
#
# This file is part of python-opentimestamps.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-opentimestamps including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

from bitcoin.core import b2lx

from opentimestamps.core.op import OpAppend, OpPrepend
from opentimestamps.op import cat_sha256d
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation

def make_btc_block_merkle_tree(blk_txid_ops):
    assert len(blk_txid_ops) > 0

    digests = blk_txid_ops
    while len(digests) > 1:
        # The famously broken Satoshi algorithm: if the # of digests at this
        # level is odd, double the last one.
        if len(digests) % 1:
            digests.append(digests[-1])

        next_level = []
        for i in range(0,len(digests),2):
            next_level.append(cat_sha256d(digests[i], digests[i + 1]))

        digests = next_level

    return digests[0]


def make_bitcoin_attestation_from_blockhash(digest_op, blockhash, proxy):
    blk = proxy.getblock(blockhash)

    # Find the transaction containing digest
    #
    # FIXME: we actually should find the _smallest_ transaction containing
    # digest to ward off trolls...
    commitment_tx = None
    prefix = None
    suffix = None
    digest = digest_op.result
    for tx in blk.vtx:
        serialized_tx = tx.serialize()

        try:
            i = serialized_tx.index(digest)
        except ValueError:
            continue

        # Found it!
        commitment_tx = tx
        prefix = serialized_tx[0:i]
        suffix = serialized_tx[i + len(digest):]

        break
    else:
        raise ValueError("Couldn't find digest in block")

    # Add the commitment ops necessary to go from the digest to the txid op
    prefix_op = OpPrepend(prefix, digest_op)
    digest_op.next_op = prefix_op

    commitment_txid_op = cat_sha256d(prefix_op, suffix)

    assert commitment_tx.GetHash() == commitment_txid_op.result

    # Create the txid list, with our commitment txid op in the appropriate
    # place
    blk_txid_ops = []
    for tx in blk.vtx:
        txid = tx.GetHash()
        if txid != commitment_txid_op.result:
            blk_txid_ops.append(txid)
        else:
            blk_txid_ops.append(commitment_txid_op)

    # Build the merkle tree
    merkleroot_op = make_btc_block_merkle_tree(blk_txid_ops)

    # FIXME: as of v0.6.0 python-bitcoinlib doesn't support the verbose option
    # for getblock(header), so we have to go a bit low-level to get the block
    # height.
    r = proxy._call('getblock', b2lx(blockhash), True)

    return BitcoinBlockHeaderAttestation(r['height'])
