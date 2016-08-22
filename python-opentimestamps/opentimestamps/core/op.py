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

class Op:
    """Operation in a commitment proof

    Each operation takes a message and transforms it to produce a result.
    Operations form a linked list, so each operation may have a next operation.
    Equally, the message may in fact be an operation, in which case the next_op of
    that operation is set appropriately.
    """
    __slots__ = ['__result','next_op']

    SUBCLS_BY_TAG = None

    @property
    def result(self):
        return self.__result

    @result.setter
    def result(self, new_result):
        try:
            self.__result
        except AttributeError:
            self.__result = new_result
        else:
            raise AttributeError("Result can't be modified once set")

    def __bytes__(self):
        return self.result

    def __str__(self):
        return self.TAG_NAME

    def __init__(self, result):
        self.__result = result
        self.next_op = None

    def final_commitment(self):
        """Get the final commitment result at the end of the commit path"""
        while self.next_op is not None:
            self = self.next_op
        return self.result

    def _serialize_op_payload(self, ctx):
        pass

    def serialize(self, ctx):
        while self is not None:
            ctx.write_bytes(self.TAG)
            self._serialize_op_payload(ctx)

            self = self.next_op
        ctx.write_bytes(b'\x00')

    @classmethod
    def _register_op(cls, subcls):
        if cls.SUBCLS_BY_TAG is None:
            cls.SUBCLS_BY_TAG = {}

        cls.SUBCLS_BY_TAG[subcls.TAG] = subcls
        return subcls

    @classmethod
    def _deserialize_op_payload(cls, ctx, msg):
        return cls(msg)

    @classmethod
    def deserialize(cls, ctx, first_result):
        # First op in the path is handled specially, and must be a
        # cryptographic op, as we need to prime it with the first result.
        tag = ctx.read_bytes(1)
        subcls = cls.SUBCLS_BY_TAG[tag]

        # FIXME: error handling
        assert issubclass(subcls, CryptOp)

        self = subcls.__new__(subcls)
        self.__result = first_result # FIXME: should check result length

        rest = self
        while True:
            tag = ctx.read_bytes(1)
            if tag == b'\x00':
                break

            # FIXME: handle unknown tag here
            subcls = cls.SUBCLS_BY_TAG[tag]

            rest.next_op = subcls._deserialize_op_payload(ctx, rest.result)
            rest = rest.next_op

        return self

class BytesCommitment(Op):
    """Commitment to a bytes instance"""

    @property
    def msg(self):
        return self.result

    def __repr__(self):
        return 'BytesCommitment(%r)' % self.result

    def __str__(self):
        return repr(self)

    def __init__(self, msg):
        self.result = msg
        self.next_op = None

@Op._register_op
class OpAppend(Op):
    TAG = b'\xf0'
    TAG_NAME = 'append'

    def __init__(self, msg, suffix):
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
class OpPrepend(Op):
    TAG = b'\xf1'
    TAG_NAME = 'prepend'

    def __init__(self, prefix, msg):
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
class OpReverse(Op):
    TAG = b'\xf2'
    TAG_NAME = 'reverse'

    def __init__(self, msg):
        super().__init__(bytes(msg)[::-1])


class CryptOp(Op):
    """Cryptographic operation

    Notably, these are the only operations that can take StreamCommitments as
    their message.
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
