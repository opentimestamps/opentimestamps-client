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

from bitcoin.core import x,b2x

class PathOp:
    def __init__(self, *args):
        pass

    def __call__(self, msg):
        raise NotImplementedError

    def to_json(self):
        return [self.OP_NAME, b2x(self.prefix), b2x(self.suffix)]

    @classmethod
    def from_json(cls, json_obj):
        optype, prefix, suffix = json_obj
        prefix = x(prefix)
        suffix = x(suffix)

        if optype == 'sha256':
            return PathOp_SHA256(prefix, suffix)

        elif optype == 'ripemd160':
            return PathOp_RIPEMD160(prefix, suffix)

        else:
            raise Exception('unknown path op %s' % optype)

class PathOp_SHA256(PathOp):
    OP_NAME = 'sha256'

    def __init__(self, prefix, suffix):
        self.prefix = prefix
        self.suffix = suffix

    def __call__(self, msg):
        msg = self.prefix + msg + self.suffix
        return hashlib.sha256(msg).digest()

class PathOp_RIPEMD160(PathOp):
    OP_NAME = 'ripemd160'

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

    @classmethod
    def from_CBlockHeader(self, blkhdr, chain='bitcoin-mainnet'):
        serialized_hdr = blkhdr.serialize()
        return BlockHeaderSig(chain, serialized_hdr[0:4+32],
                                     serialized_hdr[4+32+32:])

    def verify(self, digest, block_index):
        msg = self.prefix + digest + self.suffix
        blockhash = hashlib.sha256(hashlib.sha256(msg).digest()).digest()

        if blockhash in block_index:
            nTime = struct.unpack('<I', self.suffix[0:4])[0]
            return nTime

        else:
            raise Exception('invalid blockheader sig')

    def to_json(self):
        return ['block_header', self.chain, b2x(self.prefix), b2x(self.suffix)]

    @classmethod
    def from_json(cls, json_obj):
        sigtype, chain, prefix, suffix = json_obj
        assert sigtype == 'block_header'
        prefix = x(prefix)
        suffix = x(suffix)
        return BlockHeaderSig(chain, prefix, suffix)


class Timestamp:
    def __init__(self, path, sig):
        self.path = path
        self.sig = sig

    def verify(self, msg, block_index):
        digest = self.path(msg)

        return self.sig.verify(digest, block_index)

    def to_json(self):
        """Convert to json format"""
        path_ops = []
        for path_op in self.path:
            path_ops.append(path_op.to_json())

        return [path_ops, self.sig.to_json()]

    @classmethod
    def from_json(cls, json_obj):
        json_path_ops, json_sig = json_obj

        path_ops = [PathOp.from_json(json_path_op) for json_path_op in json_path_ops]

        sig = BlockHeaderSig.from_json(json_sig)

        return Timestamp(Path(path_ops), sig)
