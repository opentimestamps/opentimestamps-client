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
import binascii

from opentimestamps.core.notary import TimeAttestation

class Timestamp:
    """Proof that one or more attestations commit to a message

    The proof is in the form of a tree, with each node being a message, and the
    edges being operations acting on those messages. The leafs of the tree are
    attestations that attest to the time that messages in the tree existed prior.
    """
    __slots__ = ['__msg', 'ops']

    @property
    def msg(self):
        return self.__msg

    def __init__(self, msg):
        self.__msg = msg
        self.ops = []

    def __repr__(self):
        return 'Timestamp(<%s>)' % binascii.hexlify(self.__msg).decode('utf8')

    def add_op(self, op_cls, *args):
        """Add a new operation"""
        new_op = op_cls(self.__msg, *args)
        self.ops.append(new_op)
        return new_op

    def serialize(self, ctx):
        if len(self.ops) == 0:
            raise ValueError("An empty timestamp can't be serialized")

        elif len(self.ops) == 1:
            self.ops[0].serialize(ctx)

        else:
            ctx.write_bytes(b'\xff')
            for op in self.ops:
                op.serialize(ctx)
            ctx.write_bytes(b'\xfe')


class Op:
    """Timestamp proof operations

    Operations are the edges in the timestamp tree, with each operation proving
    something about a message.
    """
    SUBCLS_BY_TAG = None
    __slots__ = []

    def __init__(self, result):
        raise NotImplementedError

    @classmethod
    def _register_op(cls, subcls):
        return subcls

    def _serialize_op_payload(self, ctx):
        pass

    def serialize(self, ctx):
        ctx.write_bytes(self.TAG)
        self._serialize_op_payload(ctx)

@Op._register_op
class OpVerify(Op):
    """Verify attestation

    Verifications never have children.
    """
    __slots__ = ['__msg','attestation']

    TAG = b'\x00'
    TAG_NAME = b'verify'

    @property
    def msg(self):
        return self.__msg

    def __init__(self, msg, attestation):
        self.__msg = msg
        self.attestation = attestation

    def _serialize_op_payload(self, ctx):
        self.attestation.serialize(ctx)


class TransformOp(Op):
    """Prove that a transformation of a message is timestamped"""
    __slots__ = ['__timestamp']

    @property
    def timestamp(self):
        """Timestamp on the result"""
        return self.__timestamp

    @timestamp.setter
    def timestamp(self, new_stamp):
        """Set a new timestamp

        The new timestamp must over the same message as the old timestamp.
        """
        try:
            if self.__timestamp.msg != new_stamp.msg:
                raise ValueError("Timestamp must be for the same message as before")
        except AttributeError:
            # Not yet set
            pass
        self.__timestamp = new_stamp

    @property
    def result(self):
        """The result of this operation"""
        self.__timestamp.msg

    def __init__(self, result):
        # FIXME: check length limits on result
        self.__timestamp = Timestamp(result)


@Op._register_op
class OpAppend(TransformOp):
    """Append a suffix to a message"""
    TAG = b'\xf0'
    TAG_NAME = 'append'

    def __init__(self, msg, suffix):
        """Create a new append operation"""
        self.suffix = bytes(suffix)
        result = bytes(msg) + self.suffix
        super().__init__(result)

    def __str__(self):
        return 'append %s' % binascii.hexlify(self.suffix).decode('utf8')

    def _serialize_op_payload(self, ctx):
        ctx.write_varbytes(self.suffix)

    @classmethod
    def _deserialize_op_payload(cls, ctx, msg):
        suffix = ctx.read_varbytes(2**20) # FIXME: what should maximum be here?
        return OpAppend(msg, suffix)

@Op._register_op
class OpPrepend(TransformOp):
    TAG = b'\xf1'
    TAG_NAME = 'prepend'

    def __init__(self, msg, prefix):
        self.prefix = bytes(prefix)
        result = self.prefix + bytes(msg)
        super().__init__(result)

    def __str__(self):
        return 'prepend %s' % binascii.hexlify(self.prefix).decode('utf8')

    def _serialize_op_payload(self, ctx):
        ctx.write_varbytes(self.prefix)

    @classmethod
    def _deserialize_op_payload(cls, ctx, msg):
        prefix = ctx.read_varbytes(2**20) # FIXME: what should maximum be here?
        return OpPrepend(prefix, msg)


@Op._register_op
class OpReverse(TransformOp):
    TAG = b'\xf2'
    TAG_NAME = 'reverse'

    def __init__(self, msg):
        super().__init__(bytes(msg)[::-1])


class CryptOp(TransformOp):
    """Cryptographic transformations

    These transformations have the unique property that for any length message,
    the size of the result they return is fixed. Additionally, they're the only
    type of timestamp that can be applied directly to a stream.
    """

    def __init__(self, msg):
        hasher = hashlib.new(self.HASHLIB_NAME, bytes(msg))
        result = hasher.digest()
        super().__init__(result)

    @classmethod
    def from_fd(cls, fd):
        hasher = hashlib.new(cls.HASHLIB_NAME)
        while True:
            chunk = fd.read(2**20) # 1MB chunks
            if chunk:
                hasher.update(chunk)
            else:
                break

        result = hasher.digest()
        self = cls.__new__(cls)
        Op.__init__(self, result)
        return self

# Cryptographic operation tag numbers taken from RFC4880

@Op._register_op
class OpSHA1(CryptOp):
    # Remember that for timestamping, hash algorithms with collision attacks
    # *are* secure! We've still proven that both messages existed prior to some
    # point in time - the fact that they both have the same hash digest doesn't
    # change that.
    #
    # Heck, even md5 is still secure enough for timestamping... but that's
    # pushing our luck...
    TAG = b'\x02'
    TAG_NAME = 'sha1'
    HASHLIB_NAME = "sha1"

@Op._register_op
class OpRIPEMD160(CryptOp):
    TAG = b'\x03'
    TAG_NAME = 'ripemd160'
    HASHLIB_NAME = "ripemd160"

@Op._register_op
class OpSHA256(CryptOp):
    TAG = b'\x08'
    TAG_NAME = 'sha256'
    HASHLIB_NAME = "sha256"


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
