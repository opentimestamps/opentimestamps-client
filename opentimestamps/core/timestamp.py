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

import hashlib

from opentimestamps.core.op import Op
from opentimestamps.core.notary import TimeAttestation

class Timestamp:
    """Proof that a time attestation commits to a message

    A timestamp contains a list of commitment operations, that when applied to
    the message, produce a final commitment that the attestation attests too.
    """

    def __init__(self, path, attestation):
        self.path = path
        self.attestation = attestation

    def serialize(self, ctx):
        self.path.serialize(ctx)
        self.attestation.serialize(ctx)

    @classmethod
    def deserialize(cls, ctx, first_result):
        path = Op.deserialize(ctx, first_result)
        attestation = TimeAttestation.deserialize(ctx)
        return Timestamp(path, attestation)

class DetachedTimestampFile:
    """A file containing a timestamp for another file

    Contains a timestamp, along with a header and the digest of the file.
    """

    HEADER_MAGIC = b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94\x00'
    """Header magic bytes

    Designed to be give the user some information in a hexdump, while being
    identified as 'data' by the file utility.
    """

    @property
    def file_digest(self):
        """The digest of the file that was timestamped"""
        return self.timestamp.path.result

    @property
    def file_hash_op_class(self):
        """The op class used to hash the original file"""
        return self.timestamp.path.__class__

    def __init__(self, timestamp):
        self.timestamp = timestamp

    def serialize(self, ctx):
        ctx.write_bytes(self.HEADER_MAGIC)

        ctx.write_varbytes(self.timestamp.path.result)
        self.timestamp.serialize(ctx)

    @classmethod
    def deserialize(cls, ctx):
        header_magic = ctx.read_bytes(len(cls.HEADER_MAGIC))
        assert header_magic == cls.HEADER_MAGIC

        first_result = ctx.read_varbytes(64)
        timestamp = Timestamp.deserialize(ctx, first_result)

        return DetachedTimestampFile(timestamp)
