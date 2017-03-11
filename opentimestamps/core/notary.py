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

import opentimestamps.core.serialize

class VerificationError(Exception):
    """Attestation verification errors"""

class TimeAttestation:
    """Time-attesting signature"""

    TAG = None
    TAG_SIZE = 8

    # FIXME: What should this be?
    MAX_PAYLOAD_SIZE = 8192
    """Maximum size of a attestation payload"""

    def _serialize_payload(self, ctx):
        raise NotImplementedError

    def serialize(self, ctx):
        ctx.write_bytes(self.TAG)

        payload_ctx = opentimestamps.core.serialize.BytesSerializationContext()
        self._serialize_payload(payload_ctx)

        ctx.write_varbytes(payload_ctx.getbytes())

    def __eq__(self, other):
        """Implementation of equality operator

        WARNING: The exact behavior of this isn't yet well-defined enough to be
        used for consensus-critical applications.
        """
        if isinstance(other, TimeAttestation):
            assert self.__class__ is not other.__class__ # should be implemented by subclass
            return False

        else:
            return NotImplemented

    def __lt__(self, other):
        """Implementation of less than operator

        WARNING: The exact behavior of this isn't yet well-defined enough to be
        used for consensus-critical applications.
        """
        if isinstance(other, TimeAttestation):
            assert self.__class__ is not other.__class__ # should be implemented by subclass
            return self.TAG < other.TAG

        else:
            return NotImplemented

    @classmethod
    def deserialize(cls, ctx):
        tag = ctx.read_bytes(cls.TAG_SIZE)

        serialized_attestation = ctx.read_varbytes(cls.MAX_PAYLOAD_SIZE)

        import opentimestamps.core.serialize
        payload_ctx = opentimestamps.core.serialize.BytesDeserializationContext(serialized_attestation)

        # FIXME: probably a better way to do this...
        import opentimestamps.core.dubious.notary

        if tag == PendingAttestation.TAG:
            r = PendingAttestation.deserialize(payload_ctx)
        elif tag == BitcoinBlockHeaderAttestation.TAG:
            r = BitcoinBlockHeaderAttestation.deserialize(payload_ctx)
        elif tag == opentimestamps.core.dubious.notary.EthereumBlockHeaderAttestation.TAG:
            r = opentimestamps.core.dubious.notary.EthereumBlockHeaderAttestation.deserialize(payload_ctx)
        else:
            return UnknownAttestation(tag, serialized_attestation)

        # If attestations want to have unspecified fields for future
        # upgradability they should do so explicitly.
        payload_ctx.assert_eof()
        return r

class UnknownAttestation(TimeAttestation):
    """Placeholder for attestations that don't support"""

    def __init__(self, tag, payload):
        if tag.__class__ != bytes:
            raise TypeError("tag must be bytes instance; got %r" % tag.__class__)
        elif len(tag) != self.TAG_SIZE:
            raise ValueError("tag must be exactly %d bytes long; got %d" % (self.TAG_SIZE, len(tag)))

        if payload.__class__ != bytes:
            raise TypeError("payload must be bytes instance; got %r" % tag.__class__)
        elif len(payload) > self.MAX_PAYLOAD_SIZE:
            raise ValueError("payload must be <= %d bytes long; got %d" % (self.MAX_PAYLOAD_SIZE, len(payload)))

        # FIXME: we should check that tag != one of the tags that we do know
        # about; if it does the operators < and =, and hash() will likely act
        # strangely
        self.TAG = tag
        self.payload = payload

    def __repr__(self):
        return 'UnknownAttestation(%r, %r)' % (self.TAG, self.payload)

    def __eq__(self, other):
        if other.__class__ is UnknownAttestation:
            return self.TAG == other.TAG and self.payload == other.payload
        else:
            super().__eq__(other)

    def __lt__(self, other):
        if other.__class__ is UnknownAttestation:
            return (self.tag, self.payload) < (other.tag, other.payload)
        else:
            super().__eq__(other)

    def __hash__(self):
        return hash((self.TAG, self.payload))

    def _serialize_payload(self, ctx):
        # Notice how this is write_bytes, not write_varbytes - the latter would
        # incorrectly add a length header to the actual payload.
        ctx.write_bytes(self.payload)


# Note how neither of these signatures actually has the time...

class PendingAttestation(TimeAttestation):
    """Pending attestation

    Commitment has been recorded in a remote calendar for future attestation,
    and we have a URI to find a more complete timestamp in the future.

    Nothing other than the URI is recorded, nor is there provision made to add
    extra metadata (other than the URI) in future upgrades. The rational here
    is that remote calendars promise to keep commitments indefinitely, so from
    the moment they are created it should be possible to find the commitment in
    the calendar. Thus if you're not satisfied with the local verifiability of
    a timestamp, the correct thing to do is just ask the remote calendar if
    additional attestations are available and/or when they'll be available.

    While we could additional metadata like what types of attestations the
    remote calendar expects to be able to provide in the future, that metadata
    can easily change in the future too. Given that we don't expect timestamps
    to normally have more than a small number of remote calendar attestations,
    it'd be better to have verifiers get the most recent status of such
    information (possibly with appropriate negative response caching).

    """

    TAG = bytes.fromhex('83dfe30d2ef90c8e')

    MAX_URI_LENGTH = 1000
    """Maximum legal URI length, in bytes"""

    ALLOWED_URI_CHARS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:"
    """Characters allowed in URI's

    Note how we've left out the characters necessary for parameters, queries,
    or fragments, as well as IPv6 [] notation, percent-encoding special
    characters, and @ login notation. Hopefully this keeps us out of trouble!
    """

    @classmethod
    def check_uri(cls, uri):
        """Check URI for validity

        Raises ValueError appropriately
        """
        if len(uri) > cls.MAX_URI_LENGTH:
            raise ValueError("URI exceeds maximum length")
        for char in uri:
            if char not in cls.ALLOWED_URI_CHARS:
                raise ValueError("URI contains invalid character %r" % bytes([char]))

    def __init__(self, uri):
        if not isinstance(uri, str):
            raise TypeError("URI must be a string")
        self.check_uri(uri.encode())
        self.uri = uri

    def __repr__(self):
        return 'PendingAttestation(%r)' % self.uri

    def __eq__(self, other):
        if other.__class__ is PendingAttestation:
            return self.uri == other.uri
        else:
            super().__eq__(other)

    def __lt__(self, other):
        if other.__class__ is PendingAttestation:
            return self.uri < other.uri

        else:
            super().__eq__(other)

    def __hash__(self):
        return hash(self.uri)

    def _serialize_payload(self, ctx):
        ctx.write_varbytes(self.uri.encode())

    @classmethod
    def deserialize(cls, ctx):
        utf8_uri = ctx.read_varbytes(cls.MAX_URI_LENGTH)

        try:
            cls.check_uri(utf8_uri)
        except ValueError as exp:
            raise opentimestamps.core.serialize.DeserializationError("Invalid URI: %r" % exp)

        return PendingAttestation(utf8_uri.decode())

class BitcoinBlockHeaderAttestation(TimeAttestation):
    """Signed by the Bitcoin blockchain

    The commitment digest will be the merkleroot of the blockheader.

    The block height is recorded so that looking up the correct block header in
    an external block header database doesn't require every header to be stored
    locally (33MB and counting). (remember that a memory-constrained local
    client can save an MMR that commits to all blocks, and use an external service to fill
    in pruned details).

    Otherwise no additional redundant data about the block header is recorded.
    This is very intentional: since the attestation contains (nearly) the
    absolute bare minimum amount of data, we encourage implementations to do
    the correct thing and get the block header from a by-height index, check
    that the merkleroots match, and then calculate the time from the header
    information. Providing more data would encourage implementations to cheat.

    Remember that the only thing that would invalidate the block height is a
    reorg, but in the event of a reorg the merkleroot will be invalid anyway,
    so there's no point to recording data in the attestation like the header
    itself. At best that would just give us extra confirmation that a reorg
    made the attestation invalid; reorgs deep enough to invalidate timestamps are
    exceptionally rare events anyway, so better to just tell the user the timestamp
    can't be verified rather than add almost-never tested code to handle that case
    more gracefully.
    """

    TAG = bytes.fromhex('0588960d73d71901')

    def __init__(self, height):
        self.height = height

    def __eq__(self, other):
        if other.__class__ is BitcoinBlockHeaderAttestation:
            return self.height == other.height
        else:
            super().__eq__(other)

    def __lt__(self, other):
        if other.__class__ is BitcoinBlockHeaderAttestation:
            return self.height < other.height

        else:
            super().__eq__(other)

    def __hash__(self):
        return hash(self.height)

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

