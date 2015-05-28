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

import unittest

from bitcoin.core import x,lx,b2x,b2lx

from opentimestamps.core import *

class Test_Path(unittest.TestCase):
    def test_null_path(self):
        """Test a path with no ops"""
        null_path = Path([])

        msg = b'hello world'
        digest = null_path(msg)

        self.assertEqual(msg, digest)

class Test_BlockHeaderSig(unittest.TestCase):
    def test(self):
        sig = BlockHeaderSig('bitcoin-mainnet',
                             x('010000000000000000000000000000000000000000000000000000000000000000000000'),
                             x('29ab5f49ffff001d1dac2b7c'))

        block_index = set([lx('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')])
        nTime = sig.verify(x('3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a'), block_index)

        self.assertEqual(nTime, 1231006505)

class Test_Timestamp(unittest.TestCase):
    def test(self):
        msg = lx('0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9')

        tx_op = PathOp_SHA256(b'\x01\x00\x00\x00\x01', b'\x00\x00\x00\x00HG0D\x02 NE\xe1i2\xb8\xafQIa\xa1\xd3\xa1\xa2_\xdf?Ow2\xe9\xd6$\xc6\xc6\x15H\xab_\xb8\xcdA\x02 \x18\x15"\xec\x8e\xca\x07\xdeH`\xa4\xac\xdd\x12\x90\x9d\x83\x1c\xc5l\xbb\xacF"\x08"!\xa8v\x8d\x1d\t\x01\xff\xff\xff\xff\x02\x00\xca\x9a;\x00\x00\x00\x00CA\x04\xae\x1ab\xfe\t\xc5\xf5\x1b\x13\x90_\x07\xf0k\x99\xa2\xf7\x15\x9b"%\xf3t\xcd7\x8dq0/\xa2\x84\x14\xe7\xaa\xb3s\x97\xf5T\xa7\xdf_\x14,!\xc1\xb70;\x8a\x06&\xf1\xba\xde\xd5\xc7*pO~l\xd8L\xac\x00(k\xee\x00\x00\x00\x00CA\x04\x11\xdb\x93\xe1\xdc\xdb\x8a\x01kI\x84\x0f\x8cS\xbc\x1e\xb6\x8a8.\x97\xb1H.\xca\xd7\xb1H\xa6\x90\x9a\\\xb2\xe0\xea\xdd\xfb\x84\xcc\xf9tDd\xf8.\x16\x0b\xfa\x9b\x8bd\xf9\xd4\xc0?\x99\x9b\x86C\xf6V\xb4\x12\xa3\xac\x00\x00\x00\x00')

        merkle_op = PathOp_SHA256(lx('b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082'),b'')

        path = Path([tx_op, PathOp_SHA256(b'',b''), merkle_op, PathOp_SHA256(b'',b'')])

        sig = BlockHeaderSig('bitcoin-mainnet',
                             x('0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000'),
                             x('51b96a49ffff001d283e9e70'))

        block_index = set([lx('00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee')])

        stamp = Timestamp(path, sig)

        nTime = stamp.verify(msg, block_index)
        self.assertEqual(nTime, 1231731025)
