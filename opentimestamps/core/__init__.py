# Copyright (C) 2015 The python-opentimestamps developers
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
import struct

class PathOp:
    def __init__(self, *args):
        pass

    def __call__(self, msg):
        raise NotImplementedError

class PathOp_SHA256(PathOp):
    def __init__(self, prefix, suffix):
        self.prefix = prefix
        self.suffix = suffix

    def __call__(self, msg):
        msg = self.prefix + msg + self.suffix
        return hashlib.sha256(msg).digest()

class PathOp_SHA256D(PathOp):
    def __init__(self, prefix, suffix):
        self.prefix = prefix
        self.suffix = suffix

    def __call__(self, msg):
        msg = self.prefix + msg + self.suffix
        return hashlib.sha256(hashlib.sha256(msg).digest()).digest()

class PathOp_RIPEMD160(PathOp):
    def __init__(self, prefix, suffix):
        self.prefix = prefix
        self.suffix = suffix

    def __call__(self, msg):
        msg = self.prefix + msg + self.suffix
        return hashlib.new('ripemd160', msg).digest()


class Path(tuple):
    def __call__(self, msg):
        for op in self:
            msg = op(msg)
        return msg



class NotarySignature:
    def __init__(self):
        pass

    def verify(self, digest):
        pass


class BlockIndexProxy:
    def __init__(self, proxy):
        self.proxy = proxy

    def __contains__(self, blockhash):
        try:
            self.proxy.getblock(blockhash)
            return True
        except IndexError:
            return False


class BlockHeaderSig(NotarySignature):
    def __init__(self, chain, prefix, suffix):
        assert chain == 'bitcoin-mainnet'
        self.chain = chain
        self.prefix = prefix
        self.suffix = suffix

    def verify(self, digest, block_index):
        msg = self.prefix + digest + self.suffix
        blockhash = hashlib.sha256(hashlib.sha256(msg).digest()).digest()

        if blockhash in block_index:
            nTime = struct.unpack('<I', self.suffix[0:4])[0]
            return nTime

        else:
            raise Exception('invalid blockheader sig')


class Timestamp:
    def __init__(self, path, sig):
        self.path = path
        self.sig = sig

    def verify(self, msg, block_index):
        digest = self.path(msg)

        return self.sig.verify(digest, block_index)
