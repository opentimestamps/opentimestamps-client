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

import opentimestamps.core.serialize

class Op(tuple):
    """Timestamp proof operations

    Operations are the edges in the timestamp tree, with each operation taking
    a message and zero or more arguments to produce a result.
    """
    SUBCLS_BY_TAG = {}
    __slots__ = []

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

    def __call__(self, msg):
        """Perform the operation on a message"""
        raise NotImplementedError

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
            arg = ctx.read_varbytes(2**16)
            return cls.SUBCLS_BY_TAG[tag](arg)
        else:
            raise opentimestamps.core.serialize.DeserializationError("Unknown binary op tag 0x%0x" % tag[0])


@BinaryOp._register_op
class OpAppend(BinaryOp):
    """Append a suffix to a message"""
    TAG = b'\xf0'
    TAG_NAME = 'append'

    def __call__(self, msg):
        return msg + self[0]

@BinaryOp._register_op
class OpPrepend(BinaryOp):
    TAG = b'\xf1'
    TAG_NAME = 'prepend'

    def __call__(self, msg):
        return self[0] + msg


@UnaryOp._register_op
class OpReverse(UnaryOp):
    TAG = b'\xf2'
    TAG_NAME = 'reverse'

    def __call__(self, msg):
        import warnings
        warnings.warn("OpReverse may get removed; see https://github.com/opentimestamps/python-opentimestamps/issues/5", PendingDeprecationWarning)
        return msg[::-1]


class CryptOp(UnaryOp):
    """Cryptographic transformations

    These transformations have the unique property that for any length message,
    the size of the result they return is fixed. Additionally, they're the only
    type of timestamp that can be applied directly to a stream.
    """
    __slots__ = []
    SUBCLS_BY_TAG = {}

    def __call__(self, msg):
        return hashlib.new(self.HASHLIB_NAME, bytes(msg)).digest()

    def hash_fd(self, fd):
        hasher = hashlib.new(self.HASHLIB_NAME)
        while True:
            chunk = fd.read(2**20) # 1MB chunks
            if chunk:
                hasher.update(chunk)
            else:
                break

        return hasher.digest()

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
