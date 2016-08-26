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

import opentimestamps.core.serialize

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
        self.__msg = bytes(msg)
        self.ops = []

    def __eq__(self, other):
        if isinstance(other, Timestamp):
            return self.__msg == other.__msg and self.ops == other.ops
        else:
            return False

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

        elif len(self.ops) > 1:
            for op in self.ops[0:-1]:
                ctx.write_bytes(b'\xff')
                op.serialize(ctx)

        # Again, a zero-op timestamp is prohibited by the serialization format!
        self.ops[-1].serialize(ctx)

    @classmethod
    def deserialize(cls, ctx, initial_msg):
        """Deserialize

        Because the serialization format doesn't include the message that the
        timestamp operates on, you have to provide it so that the correct
        operation results can be calculated.
        """
        self = cls(initial_msg)

        tag = ctx.read_bytes(1)
        while tag == b'\xff':
            op = Op.deserialize(ctx, initial_msg)
            self.ops.append(op)
            tag = ctx.read_bytes(1)

        op = Op.deserialize_from_tag(ctx, initial_msg, tag)
        self.ops.append(op)

        return self

    def verifications(self):
        """Iterate over the verifications on this timestamp"""
        for op in self.ops:
            if isinstance(op, OpVerify):
                yield op
            else:
                yield from op.timestamp.verifications()

    def str_tree(self, indent=0):
        """Convert to tree (for debugging)"""
        r = ""
        for op in self.ops:
            r += " "*indent + "%s"%str(op) + "\n"
            if isinstance(op, TransformOp):
                r += op.timestamp.str_tree(indent + 4)
        return r

class Op:
    """Timestamp proof operations

    Operations are the edges in the timestamp tree, with each operation proving
    something about a message.
    """
    SUBCLS_BY_TAG = {}
    __slots__ = []

    def __init__(self, result):
        raise NotImplementedError

    def __eq__(self, other):
        raise NotImplementedError

    def __str__(self):
        return '%s' % self.TAG_NAME

    @classmethod
    def _register_op(cls, subcls):
        cls.SUBCLS_BY_TAG[subcls.TAG] = subcls
        if cls != Op:
            cls.__base__._register_op(subcls)
        return subcls

    def _serialize_op_payload(self, ctx):
        pass

    def serialize(self, ctx):
        ctx.write_bytes(self.TAG)
        self._serialize_op_payload(ctx)

    @classmethod
    def _deserialize_op_payload(cls, ctx, initial_msg):
        return cls(initial_msg)

    @classmethod
    def deserialize_from_tag(cls, ctx, initial_msg, tag):
        if not tag in cls.SUBCLS_BY_TAG:
            raise opentimestamps.core.serialize.DeserializationError("Unknown operation tag 0x%0x" % tag[0])

        return cls.SUBCLS_BY_TAG[tag]._deserialize_op_payload(ctx, initial_msg)

    @classmethod
    def deserialize(cls, ctx, initial_msg):
        tag = ctx.read_bytes(1)
        return cls.deserialize_from_tag(ctx, initial_msg, tag)

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

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.__msg == other.__msg
                and self.attestation == other.attestation)

    def __str__(self):
        return '%s %s' % (self.TAG_NAME, self.attestation)

    def _serialize_op_payload(self, ctx):
        self.attestation.serialize(ctx)

    @classmethod
    def _deserialize_op_payload(cls, ctx, initial_msg):
        attestation = TimeAttestation.deserialize(ctx)
        return cls(initial_msg, attestation)

class TransformOp(Op):
    """Prove that a transformation of a message is timestamped"""
    __slots__ = ['__timestamp']

    SUBCLS_BY_TAG = {}

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
        return self.__timestamp.msg

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.__timestamp == other.__timestamp)

    def __init__(self, result):
        # FIXME: check length limits on result
        self.__timestamp = Timestamp(result)

    def serialize(self, ctx):
        super().serialize(ctx)
        self.__timestamp.serialize(ctx)

    @classmethod
    def _deserialize_transform_op_payload(cls, ctx, initial_msg):
        return cls(initial_msg)

    @classmethod
    def _deserialize_op_payload(cls, ctx, initial_msg):
        self = cls._deserialize_transform_op_payload(ctx, initial_msg)
        self.__timestamp = Timestamp.deserialize(ctx, self.result)
        return self


@TransformOp._register_op
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
    def _deserialize_transform_op_payload(cls, ctx, initial_msg):
        suffix = ctx.read_varbytes(2**20) # FIXME: what should maximum be here?
        return OpAppend(initial_msg, suffix)

@TransformOp._register_op
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
    def _deserialize_transform_op_payload(cls, ctx, initial_msg):
        prefix = ctx.read_varbytes(2**20) # FIXME: what should maximum be here?
        return OpPrepend(initial_msg, prefix)


@TransformOp._register_op
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
    __slots__ = []
    SUBCLS_BY_TAG = {}

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
        TransformOp.__init__(self, result)
        return self

    @classmethod
    def deserialize_from_initial_result(cls, ctx, initial_result):
        tag = ctx.read_bytes(1)
        if not tag in cls.SUBCLS_BY_TAG:
            raise opentimestamps.core.serialize.DeserializationError("Unknown operation tag 0x%0x" % tag[0])

        subcls = cls.SUBCLS_BY_TAG[tag]
        self = subcls.__new__(subcls)
        TransformOp.__init__(self, initial_result)
        self.timestamp = Timestamp.deserialize(ctx, initial_result)
        return self

# Cryptographic operation tag numbers taken from RFC4880

@CryptOp._register_op
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

@CryptOp._register_op
class OpRIPEMD160(CryptOp):
    TAG = b'\x03'
    TAG_NAME = 'ripemd160'
    HASHLIB_NAME = "ripemd160"

@CryptOp._register_op
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
        return self.timestamp_op.result

    @property
    def file_hash_op_class(self):
        """The op class used to hash the original file"""
        return self.timestamp_op.__class__

    def __init__(self, timestamp_op):
        self.timestamp_op = timestamp_op

    def __repr__(self):
        return 'DetachedTimestampFile(<%s:%s>)' % (str(self.timestamp_op), binascii.hexlify(self.file_digest).decode('utf8'))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.timestamp_op == other.timestamp_op)

    @classmethod
    def from_fd(cls, op_cls, fd):
        timestamp_op = op_cls.from_fd(fd)
        return cls(timestamp_op)

    def hash_fd(self, fd):
        """Hash a stream with the same hashing algorithm we have

        Returns a new CryptOp, whose result can be checked against
        self.timestamp_op
        """
        return self.timestamp_op.__class__.from_fd(fd)

    def serialize(self, ctx):
        ctx.write_bytes(self.HEADER_MAGIC)

        ctx.write_varbytes(self.timestamp_op.result)
        self.timestamp_op.serialize(ctx)

    @classmethod
    def deserialize(cls, ctx):
        header_magic = ctx.read_bytes(len(cls.HEADER_MAGIC))
        assert header_magic == cls.HEADER_MAGIC

        first_result = ctx.read_varbytes(64)
        timestamp_op = CryptOp.deserialize_from_initial_result(ctx, first_result)

        return DetachedTimestampFile(timestamp_op)
