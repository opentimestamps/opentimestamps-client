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

import binascii
import hashlib
import sha3
import opentimestamps.core.serialize

class MsgValueError(ValueError):
    """Raised when an operation can't be applied to the specified message.

    For example, because OpHexlify doubles the size of it's input, we restrict
    the size of the message it can be applied to to avoid running out of
    memory; OpHexlify raises this exception when that happens.
    """

class OpArgValueError(ValueError):
    """Raised when an operation argument has an invalid value

    For example, if OpAppend/OpPrepend's argument is too long.
    """

class Op(tuple):
    """Timestamp proof operations

    Operations are the edges in the timestamp tree, with each operation taking
    a message and zero or more arguments to produce a result.
    """
    SUBCLS_BY_TAG = {}
    __slots__ = []

    MAX_RESULT_LENGTH = 4096
    """Maximum length of an Op result

    For a verifier, this limit is what limits the maximum amount of memory you
    need at any one time to verify a particular timestamp path; while verifying
    a particular commitment operation path previously calculated results can be
    discarded.

    Of course, if everything was a merkle tree you never need to append/prepend
    anything near 4KiB of data; 64 bytes would be plenty even with SHA512. The
    main need for this is compatibility with existing systems like Bitcoin
    timestamps and Certificate Transparency servers. While the pathological
    limits required by both are quite large - 1MB and 16MiB respectively - 4KiB
    is perfectly adequate in both cases for more reasonable usage.

    Op subclasses should set this limit even lower if doing so is appropriate
    for them.
    """

    MAX_MSG_LENGTH = 4096
    """Maximum length of the message an Op can be applied too

    Similar to the result length limit, this limit gives implementations a sane
    constraint to work with; the maximum result-length limit implicitly
    constrains maximum message length anyway.

    Op subclasses should set this limit even lower if doing so is appropriate
    for them.
    """

    def __eq__(self, other):
        if isinstance(other, Op):
            return self.TAG == other.TAG and tuple(self) == tuple(other)
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Op):
            return self.TAG != other.TAG or tuple(self) != tuple(other)
        else:
            return NotImplemented

    def __lt__(self, other):
        if isinstance(other, Op):
            if self.TAG == other.TAG:
                return tuple(self) < tuple(other)
            else:
                return self.TAG < other.TAG
        else:
            return NotImplemented

    def __le__(self, other):
        if isinstance(other, Op):
            if self.TAG == other.TAG:
                return tuple(self) <= tuple(other)
            else:
                return self.TAG < other.TAG
        else:
            return NotImplemented

    def __gt__(self, other):
        if isinstance(other, Op):
            if self.TAG == other.TAG:
                return tuple(self) > tuple(other)
            else:
                return self.TAG > other.TAG
        else:
            return NotImplemented
    def __ge__(self, other):
        if isinstance(other, Op):
            if self.TAG == other.TAG:
                return tuple(self) >= tuple(other)
            else:
                return self.TAG > other.TAG
        else:
            return NotImplemented

    def __hash__(self):
        return self.TAG[0] ^ tuple.__hash__(self)

    def _do_op_call(self, msg):
        raise NotImplementedError

    def __call__(self, msg):
        """Apply the operation to a message

        Raises MsgValueError if the message value is invalid, such as it being
        too long, or it causing the result to be too long.
        """
        if not isinstance(msg, bytes):
            raise TypeError("Expected message to be bytes; got %r" % msg.__class__)

        elif len(msg) > self.MAX_MSG_LENGTH:
            raise MsgValueError("Message too long; %d > %d" % (len(msg), self.MAX_MSG_LENGTH))

        r = self._do_op_call(msg)

        # No operation should allow the result to be empty; that would
        # trivially allow the commitment DAG to have a cycle in it.
        assert len(r)

        if len(r) > self.MAX_RESULT_LENGTH:
            raise MsgValueError("Result too long; %d > %d" % (len(r), self.MAX_RESULT_LENGTH))

        else:
            return r

    def __repr__(self):
        return '%s()' % self.__class__.__name__

    def __str__(self):
        return '%s' % self.TAG_NAME

    @classmethod
    def _register_op(cls, subcls):
        cls.SUBCLS_BY_TAG[subcls.TAG] = subcls
        if cls != Op:
            cls.__base__._register_op(subcls)
        return subcls

    def serialize(self, ctx):
        ctx.write_bytes(self.TAG)

    @classmethod
    def deserialize_from_tag(cls, ctx, tag):
        if tag in cls.SUBCLS_BY_TAG:
            return cls.SUBCLS_BY_TAG[tag].deserialize_from_tag(ctx, tag)
        else:
            raise opentimestamps.core.serialize.DeserializationError("Unknown operation tag 0x%0x" % tag[0])

    @classmethod
    def deserialize(cls, ctx):
        tag = ctx.read_bytes(1)
        return cls.deserialize_from_tag(ctx, tag)

class UnaryOp(Op):
    """Operations that act on a single message"""
    SUBCLS_BY_TAG = {}

    def __new__(cls):
        return tuple.__new__(cls)

    def serialize(self, ctx):
        super().serialize(ctx)

    @classmethod
    def deserialize_from_tag(cls, ctx, tag):
        if tag in cls.SUBCLS_BY_TAG:
            return cls.SUBCLS_BY_TAG[tag]()
        else:
            raise opentimestamps.core.serialize.DeserializationError("Unknown unary op tag 0x%0x" % tag[0])

class BinaryOp(Op):
    """Operations that act on a message and a single argument"""
    SUBCLS_BY_TAG = {}

    def __new__(cls, arg):
        if not isinstance(arg, bytes):
            raise TypeError("arg must be bytes")
        elif not len(arg):
            raise OpArgValueError("%s arg can't be empty" % cls.__name__)
        elif len(arg) > cls.MAX_RESULT_LENGTH:
            raise OpArgValueError("%s arg too long: %d > %d" % (cls.__name__, len(arg), cls.MAX_RESULT_LENGTH))
        return tuple.__new__(cls, (arg,))

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self[0])

    def __str__(self):
        return '%s %s' % (self.TAG_NAME, binascii.hexlify(self[0]).decode('utf8'))

    def serialize(self, ctx):
        super().serialize(ctx)
        ctx.write_varbytes(self[0])

    @classmethod
    def deserialize_from_tag(cls, ctx, tag):
        if tag in cls.SUBCLS_BY_TAG:
            arg = ctx.read_varbytes(cls.MAX_RESULT_LENGTH, min_len=1)
            return cls.SUBCLS_BY_TAG[tag](arg)
        else:
            raise opentimestamps.core.serialize.DeserializationError("Unknown binary op tag 0x%0x" % tag[0])


@BinaryOp._register_op
class OpAppend(BinaryOp):
    """Append a suffix to a message"""
    TAG = b'\xf0'
    TAG_NAME = 'append'

    def _do_op_call(self, msg):
        return msg + self[0]

@BinaryOp._register_op
class OpPrepend(BinaryOp):
    """Prepend a prefix to a message"""
    TAG = b'\xf1'
    TAG_NAME = 'prepend'

    def _do_op_call(self, msg):
        return self[0] + msg


@UnaryOp._register_op
class OpReverse(UnaryOp):
    TAG = b'\xf2'
    TAG_NAME = 'reverse'

    def _do_op_call(self, msg):
        if not len(msg):
            raise MsgValueError("Can't reverse an empty message")

        import warnings
        warnings.warn("OpReverse may get removed; see https://github.com/opentimestamps/python-opentimestamps/issues/5", PendingDeprecationWarning)
        return msg[::-1]

@UnaryOp._register_op
class OpHexlify(UnaryOp):
    """Convert bytes to lower-case hexadecimal representation

    Note that hexlify can only be performed on messages that aren't empty;
    hexlify on an empty message would create a cycle in the commitment graph.
    """
    TAG = b'\xf3'
    TAG_NAME = 'hexlify'

    MAX_MSG_LENGTH = UnaryOp.MAX_RESULT_LENGTH // 2
    """Maximum length of message that we'll hexlify

    Every invocation of hexlify doubles the size of its input, this is simply
    half the maximum result length.
    """

    def _do_op_call(self, msg):
        if not len(msg):
            raise MsgValueError("Can't hexlify an empty message")
        return binascii.hexlify(msg)


class CryptOp(UnaryOp):
    """Cryptographic transformations

    These transformations have the unique property that for any length message,
    the size of the result they return is fixed. Additionally, they're the only
    type of operation that can be applied directly to a stream.
    """
    __slots__ = []
    SUBCLS_BY_TAG = {}

    DIGEST_LENGTH = None

    def _do_op_call(self, msg):
        r = hashlib.new(self.HASHLIB_NAME, bytes(msg)).digest()
        assert len(r) == self.DIGEST_LENGTH
        return r

    def hash_fd(self, fd):
        hasher = hashlib.new(self.HASHLIB_NAME)
        while True:
            chunk = fd.read(2**20) # 1MB chunks
            if chunk:
                hasher.update(chunk)
            else:
                break

        return hasher.digest()

# Cryptographic operation tag numbers taken from RFC4880, although it's not
# guaranteed that they'll continue to match that RFC in the future.

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
    DIGEST_LENGTH = 20

@CryptOp._register_op
class OpRIPEMD160(CryptOp):
    TAG = b'\x03'
    TAG_NAME = 'ripemd160'
    HASHLIB_NAME = "ripemd160"
    DIGEST_LENGTH = 20

@CryptOp._register_op
class OpSHA256(CryptOp):
    TAG = b'\x08'
    TAG_NAME = 'sha256'
    HASHLIB_NAME = "sha256"
    DIGEST_LENGTH = 32


@CryptOp._register_op
class OpKECCAK256(UnaryOp):
    __slots__ = []
    TAG = b'\x67'
    TAG_NAME = 'keccak256'
    DIGEST_LENGTH = 32

    def _do_op_call(self, msg):
        r = sha3.keccak_256(bytes(msg)).digest()
        assert len(r) == self.DIGEST_LENGTH
        return r
