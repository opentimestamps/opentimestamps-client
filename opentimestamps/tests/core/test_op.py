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

from opentimestamps.core.op import *

class Test_Op(unittest.TestCase):
    def test_append(self):
        b = BytesCommitment(b'msg')
        op_append = OpAppend(b, b'suffix')
        self.assertEqual(b.final_commitment(), b'msgsuffix')
        self.assertIs(b.next_op, op_append)

    def test_prepend(self):
        b = BytesCommitment(b'msg')
        op_prepend = OpPrepend(b'prefix', b)
        self.assertEqual(b.final_commitment(), b'prefixmsg')
        self.assertIs(b.next_op, op_prepend)

    def test_reverse(self):
        b = BytesCommitment(b'abcd')
        op_reverse = OpReverse(b)
        self.assertEqual(b.final_commitment(), b'dcba')
        self.assertIs(b.next_op, op_reverse)

    def test_sha256(self):
        b = BytesCommitment(b'')
        op_sha256 = OpSHA256(b)
        self.assertEqual(b.final_commitment(), bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))
        self.assertIs(b.next_op, op_sha256)

    def test_ripemd160(self):
        b = BytesCommitment(b'')
        op_ripemd160 = OpRIPEMD160(b)
        self.assertEqual(b.final_commitment(), bytes.fromhex('9c1185a5c5e9fc54612808977ee8f548b2258d31'))
        self.assertIs(b.next_op, op_ripemd160)
