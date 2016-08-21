# Copyright (C) 2016 The python-opentimestamps developers
#
# This file is part of python-opentimestamps.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import hashlib

class Op:
    """Operation in a commitment proof

    Each operation takes a message and transforms it to produce a result.
    Operations form a linked list, so each operation may have a next operation.
    Equally, the message may in fact be an operation, in which case the next_op of
    that operation is set appropriately.
    """
    __slots__ = ['__result','next_op']

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

    def __init__(self, result):
        self.__result = result
        self.next_op = None

    def final_commitment(self):
        """Get the final commitment result at the end of the commit path"""
        while self.next_op is not None:
            self = self.next_op
        return self.result

class BytesCommitment(Op):
    """Commitment to a bytes instance"""

    @property
    def msg(self):
        return self.result

    def __repr__(self):
        return 'BytesCommitment(%r)' % self.result

    def __init__(self, msg):
        self.result = msg
        self.next_op = None

class OpAppend(Op):
    def __init__(self, msg, suffix):
        result = bytes(msg) + bytes(suffix)
        super().__init__(result)

class OpPrepend(Op):
    def __init__(self, prefix, msg):
        result = bytes(prefix) + bytes(msg)
        super().__init__(result)


class OpReverse(Op):
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
        hasher = hashlib.new(self.HASHLIB_NAME)
        while True:
            chunk = fd.read(2**20) # 1MB chunks
            if chunk:
                hasher.update(chunk)
            else:
                break

        result = hasher.digest()
        self = cls.__new__()
        super(self).__init__(result)
        return self


class OpSHA256(CryptOp):
    HASHLIB_NAME = "sha256"

class OpRIPEMD160(CryptOp):
    HASHLIB_NAME = "ripemd160"
