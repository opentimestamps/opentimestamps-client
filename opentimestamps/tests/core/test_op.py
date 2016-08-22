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

import unittest

from opentimestamps.core.op import *

class Test_Op(unittest.TestCase):
    def test_append(self):
        b = BytesCommitment(b'msg')
        op_append = OpAppend(b, b'suffix')
        b.next_op = op_append
        self.assertEqual(b.final_commitment(), b'msgsuffix')

    def test_prepend(self):
        b = BytesCommitment(b'msg')
        op_prepend = OpPrepend(b'prefix', b)
        b.next_op = op_prepend
        self.assertEqual(b.final_commitment(), b'prefixmsg')

    def test_reverse(self):
        b = BytesCommitment(b'abcd')
        op_reverse = OpReverse(b)
        b.next_op = op_reverse
        self.assertEqual(b.final_commitment(), b'dcba')

    def test_sha256(self):
        b = BytesCommitment(b'')
        op_sha256 = OpSHA256(b)
        b.next_op = op_sha256
        self.assertEqual(b.final_commitment(), bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))

    def test_ripemd160(self):
        b = BytesCommitment(b'')
        op_ripemd160 = OpRIPEMD160(b)
        b.next_op = op_ripemd160
        self.assertEqual(b.final_commitment(), bytes.fromhex('9c1185a5c5e9fc54612808977ee8f548b2258d31'))
