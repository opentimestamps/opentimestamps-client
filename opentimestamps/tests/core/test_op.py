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
        """Append operation"""
        self.assertEqual(OpAppend(b'suffix')(b'msg'), b'msgsuffix')

    def test_prepend(self):
        """Prepend operation"""
        self.assertEqual(OpPrepend(b'prefix')(b'msg'), b'prefixmsg')

#    def test_reverse(self):
#        """Reverse operation"""
#        self.assertEqual(OpReverse()(b'abcd'), b'dcba')

    def test_reverse(self):
        """Hexlify operation"""
        for msg, expected in ((b'', b''),
                              (b'\x00', b'00'),
                              (b'\xde\xad\xbe\xef', b'deadbeef')):
            self.assertEqual(OpHexlify()(msg), expected)

    def test_sha256(self):
        """SHA256 operation"""
        self.assertEqual(OpSHA256()(b''), bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))

    def test_ripemd160(self):
        """RIPEMD160 operation"""
        self.assertEqual(OpRIPEMD160()(b''), bytes.fromhex('9c1185a5c5e9fc54612808977ee8f548b2258d31'))

    def test_equality(self):
        """Operation equality"""
        self.assertEqual(OpReverse(), OpReverse())
        self.assertNotEqual(OpReverse(), OpSHA1())

        self.assertEqual(OpAppend(b'foo'), OpAppend(b'foo'))
        self.assertNotEqual(OpAppend(b'foo'), OpAppend(b'bar'))
        self.assertNotEqual(OpAppend(b'foo'), OpPrepend(b'foo'))

    def test_ordering(self):
        """Operation ordering"""
        self.assertTrue(OpSHA1() < OpRIPEMD160())
        # FIXME: more tests
