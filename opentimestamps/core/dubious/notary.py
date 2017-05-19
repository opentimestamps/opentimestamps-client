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

"""Dubious Timestamp signature verification"""

import opentimestamps.core.serialize
import opentimestamps.core.notary as notary


class EthereumBlockHeaderAttestation(notary.TimeAttestation):
    """Signed by the Ethereum blockchain

    The commitment digest will be the merkleroot of the blockheader.

    Ethereum attestations are in the "dubious" module as what exactly Ethereum
    is has changed repeatedly in the past due to consensus failures and forks;
    as of writing the Ethereum developers plan to radically change Ethereum's
    consensus model to proof-of-stake, whose security model is at best dubious.
    """

    TAG = bytes.fromhex('30fe8087b5c7ead7')

    def __init__(self, height):
        self.height = height

    def __eq__(self, other):
        if other.__class__ is EthereumBlockHeaderAttestation:
            return self.height == other.height
        else:
            super().__eq__(other)

    def __lt__(self, other):
        if other.__class__ is EthereumBlockHeaderAttestation:
            return self.height < other.height

        else:
            super().__lt__(other)

    def __hash__(self):
        return hash(self.height)

    def verify_against_blockheader(self, digest, block):
        """Verify attestation against a block header

        Returns the block time on success; raises VerificationError on failure.
        """

        if len(digest) != 32:
            raise opentimestamps.core.notary.VerificationError("Expected digest with length 32 bytes; got %d bytes" % len(digest))
        elif digest != bytes.fromhex(block['transactionsRoot'][2:]):
            raise opentimestamps.core.notary.VerificationError("Digest does not match merkleroot")

        return block['timestamp']

    def __repr__(self):
        return 'EthereumBlockHeaderAttestation(%r)' % self.height

    def _serialize_payload(self, ctx):
        ctx.write_varuint(self.height)

    @classmethod
    def deserialize(cls, ctx):
        height = ctx.read_varuint()
        return EthereumBlockHeaderAttestation(height)
