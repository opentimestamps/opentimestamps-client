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

"""Timestamp signature verification"""

class VerificationError(Exception):
    """Attestation verification errors"""

class TimeAttestation:
    """Time-attesting signature"""

    def _serialize_payload(self, ctx):
        raise NotImplementedError

    def serialize(self, ctx):
        ctx.write_bytes(self.TAG)
        self._serialize_payload(ctx)

    @classmethod
    def deserialize(cls, ctx):
        tag = ctx.read_bytes(8)

        if tag == PendingAttestation.TAG:
            return PendingAttestation.deserialize(ctx)
        elif tag == BitcoinBlockHeaderAttestation.TAG:
            return BitcoinBlockHeaderAttestation.deserialize(ctx)

# Note how neither of these signatures actually has the time...

class PendingAttestation(TimeAttestation):
    """Pending attestation

    Commitment has been submitted for future attestation, and we have a URI to
    use to try to find out more information.
    """

    TAG = bytes.fromhex('83dfe30d2ef90c8d')

    # FIXME: what characters are allowed in uri's?
    def __init__(self, uri):
        self.uri = uri

    def __repr__(self):
        return 'PendingAttestation(%r)' % self.uri

    def _serialize_payload(self, ctx):
        ctx.write_varbytes(self.uri)

    @classmethod
    def deserialize(cls, ctx):
        uri = ctx.read_varbytes(4096) # FIXME: what should this limit be?
        return PendingAttestation(uri)

class BitcoinBlockHeaderAttestation(TimeAttestation):
    """Signed by the Bitcoin blockchain

    The commitment digest will be the merkleroot of the blockheader; the block
    height is recorded so that looking up the correct block header in an
    external block header database doesn't require every header to be stored
    locally (33MB and counting). (remember that a memory-constrained local
    client can save an MMR that commits to all blocks, and use an external service
    to fill in pruned details).
    """

    TAG = bytes.fromhex('0588960d73d71900')

    def __init__(self, height):
        self.height = height

    def verify_against_blockheader(self, digest, block_header):
        """Verify attestation against a block header

        Returns the block time on success; raises VerificationError on failure.
        """

        if len(digest) != 32:
            raise VerificationError("Expected digest with length 32 bytes; got %d bytes" % len(digest))
        elif digest != block_header.hashMerkleRoot:
            raise VerificationError("Digest does not match merkleroot")

        return block_header.nTime

    def __repr__(self):
        return 'BitcoinBlockHeaderAttestation(%r)' % self.height

    def _serialize_payload(self, ctx):
        ctx.write_varuint(self.height)

    @classmethod
    def deserialize(cls, ctx):
        height = ctx.read_varuint()
        return BitcoinBlockHeaderAttestation(height)
