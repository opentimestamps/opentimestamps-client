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

from opentimestamps.core.timestamp import *
from opentimestamps.timestamp import *

class Test_cat_sha256(unittest.TestCase):
    def test(self):
        left = Timestamp(b'foo')
        right = Timestamp(b'bar')

        stamp_left_right= cat_sha256(left, right)
        self.assertEqual(stamp_left_right.msg, bytes.fromhex('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2'))

        righter = Timestamp(b'baz')
        stamp_righter = cat_sha256(stamp_left_right, righter)
        self.assertEqual(stamp_righter.msg, bytes.fromhex('23388b16c66f1fa37ef14af8eb081712d570813e2afb8c8ae86efa726f3b7276'))


class Test_make_merkle_tree(unittest.TestCase):
    def test(self):
        def T(n, expected_merkle_root):
            roots = [Timestamp(bytes([i])) for i in range(n)]
            tip = make_merkle_tree(roots)

            self.assertEqual(tip.msg, expected_merkle_root)

            for root in roots:
                pass # FIXME: check all roots lead to same timestamp

        # Returned unchanged!
        T(1, bytes.fromhex('00'))

        # Manually calculated w/ pen-and-paper
        T(2, bytes.fromhex('b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2'))
        T(3, bytes.fromhex('e6aa639123d8aac95d13d365ec3779dade4b49c083a8fed97d7bfc0d89bb6a5e'))
        T(4, bytes.fromhex('7699a4fdd6b8b6908a344f73b8f05c8e1400f7253f544602c442ff5c65504b24'))
        T(5, bytes.fromhex('aaa9609d0c949fee22c1c941a4432f32dc1c2de939e4af25207f0dc62df0dbd8'))
        T(6, bytes.fromhex('ebdb4245f648b7e77b60f4f8a99a6d0529d1d372f98f35478b3284f16da93c06'))
        T(7, bytes.fromhex('ba4603a311279dea32e8958bfb660c86237157bf79e6bfee857803e811d91b8f'))
