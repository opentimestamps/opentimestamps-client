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

import dbm
import git
import tempfile

from bitcoin.core import b2x

from opentimestamps.core.timestamp import *
from opentimestamps.core.op import *
from opentimestamps.core.git import *

class Test_GitTreeTimestamper(unittest.TestCase):

    def setUp(self):
        self.db_dirs = []

    def tearDown(self):
        for d in self.db_dirs:
            d.cleanup()
        del self.db_dirs

    def make_stamper(self, commit):
        # Yes, we're using our own git repo as the test data!
        repo = git.Repo(__file__ + '../../../../../')
        db_dir = tempfile.TemporaryDirectory()
        self.db_dirs.append(db_dir)
        db = dbm.open(db_dir.name + '/db', 'c')
        tree = repo.commit(commit).tree
        return GitTreeTimestamper(tree, db=db)

    def test_blobs(self):
        """Git blob hashing"""

        stamper = self.make_stamper("53c68bc976c581636b84c82fe814fab178adf8a6")

        for expected_hexdigest, path in (('9e34b52cfa5724a4d87e9f7f47e2699c14d918285a20bf47f5a2a7345999e543', 'LICENSE'),
                                         ('ef83ecaca007e8afbfcca834b75510a98b6c10036374bb0d9f42a63f69efcd11', 'opentimestamps/__init__.py'),
                                         ('ef83ecaca007e8afbfcca834b75510a98b6c10036374bb0d9f42a63f69efcd11', 'opentimestamps/tests/__init__.py'),
                                         ('745bd9059cf01edabe3a61198fe1147e01ff57eec69e29f2e617b8e376427082', 'opentimestamps/tests/core/test_core.py'),
                                         ('ef83ecaca007e8afbfcca834b75510a98b6c10036374bb0d9f42a63f69efcd11', 'opentimestamps/tests/core/__init__.py'),
                                         ('7cd2b5a8723814be27fe6b224cc76e52275b1ff149de157ce374d290d032e875', 'opentimestamps/core/__init__.py'),
                                         ('d41fb0337e687b26f3f5dd61d10ec5080ff0bdc32f90f2022f7e2d9eeba91442', 'README')):

            stamp = stamper[path]
            actual_hexdigest = b2x(stamp.file_digest)
            self.assertEqual(expected_hexdigest, actual_hexdigest)

        stamper = self.make_stamper("30f6c357d578e0921dc6fffd67e2af1ce1ca0ff2")
        empty_stamp = stamper["empty"]
        self.assertEqual(empty_stamp.file_digest, bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

    def test_empty_tree(self):
        """Git tree with a single empty file"""
        stamper = self.make_stamper("30f6c357d578e0921dc6fffd67e2af1ce1ca0ff2")

        # There's a single empty file in this directory. Thus the nonce_key is:
        nonce_key = OpSHA256()(OpSHA256()(b'') + # one empty file
                               b'\x01\x89\x08\x0c\xfb\xd0\xe8\x08') # tag

        nonce1 = OpSHA256()(OpSHA256()(b'') + nonce_key)
        assert nonce1[0] & 0b1 == 1
        nonce2 = OpSHA256()(nonce1)

        self.assertEqual(stamper.timestamp.msg,
                         OpSHA256()(b''))
        self.assertEqual(stamper.timestamp.msg, b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U")

    def test_two_file_tree(self):
        """Git tree with a two files"""
        stamper = self.make_stamper("78eb5cdc1ec638be72d6fb7a38c4d24f2be5d081")

        nonce_key = OpSHA256()(OpSHA256()(b'a\n') +
                               OpSHA256()(b'b\n') +
                               b'\x01\x89\x08\x0c\xfb\xd0\xe8\x08') # tag

        n_a_nonce1 = OpSHA256()(OpSHA256()(b'a\n') + nonce_key)
        assert n_a_nonce1[0] & 0b1 == 0
        n_a_nonce2 = OpSHA256()(n_a_nonce1)
        n_a = OpSHA256()(OpSHA256()(b'a\n') + n_a_nonce2)

        n_b_nonce1 = OpSHA256()(OpSHA256()(b'b\n') + nonce_key)
        assert n_b_nonce1[0] & 0b1 == 0
        n_b_nonce2 = OpSHA256()(n_b_nonce1)
        n_b = OpSHA256()(OpSHA256()(b'b\n') + n_b_nonce2)

        self.assertEqual(stamper.timestamp.msg,
                         OpSHA256()(n_a + n_b))
        self.assertEqual(stamper.timestamp.msg, b's\x0e\xc2h\xd4\xb3\xa5\xd4\xe6\x0e\xe9\xb2t\x89@\x95\xc8c_F3\x81a=\xc2\xd4qy\xaf\x8e\xa0\x87')

    def test_tree_with_children(self):
        """Git tree with child trees"""
        stamper = self.make_stamper("b22192fffb9aad27eb57986e7fe89f8047340346")

        # These correspond to the final values from the test_empty_tree() and
        # test_two_file_tree() test cases above; git git commit we're testing
        # has the trees associated with those test cases in the one/ and two/
        # directories respectively.
        d_one = b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U"
        d_two = b's\x0e\xc2h\xd4\xb3\xa5\xd4\xe6\x0e\xe9\xb2t\x89@\x95\xc8c_F3\x81a=\xc2\xd4qy\xaf\x8e\xa0\x87'

        nonce_key = OpSHA256()(d_one + d_two +
                               b'\x01\x89\x08\x0c\xfb\xd0\xe8\x08') # tag

        n_one_nonce1 = OpSHA256()(d_one + nonce_key)
        assert n_one_nonce1[0] & 0b1 == 0
        n_one_nonce2 = OpSHA256()(n_one_nonce1)
        n_one = OpSHA256()(d_one + n_one_nonce2)

        n_two_nonce1 = OpSHA256()(d_two + nonce_key)
        assert n_two_nonce1[0] & 0b1 == 0
        n_two_nonce2 = OpSHA256()(n_two_nonce1)
        n_two = OpSHA256()(d_two + n_two_nonce2)

        self.assertEqual(stamper.timestamp.msg,
                         OpSHA256()(n_one + n_two))

    def test_tree_with_prefix_matching_blob(self):
        """Git tree with prefix matching blob"""
        stamper = self.make_stamper("75736a2524c624c1a08a574938686f83de5a8a86")

        two_a_stamp = stamper['two/a']

    def test_submodule(self):
        """Git tree with submodule"""
        stamper = self.make_stamper("a3efe73f270866bc8d8f6ce01d22c02f14b21a1a")

        self.assertEqual(stamper.timestamp.msg,
                         OpSHA256()(bytes.fromhex('48b96efa66e2958e955a31a7d9b8f2ac8384b8b9')))

    def test_dangling_symlink(self):
        """Git tree with dangling symlink"""
        stamper = self.make_stamper("a59620c107a67c4b6323e6e96aed9929d6a89618")

        self.assertEqual(stamper.timestamp.msg,
                         OpSHA256()(b'does-not-exist'))

    def test_huge_tree(self):
        """Really big git tree"""
        # would cause the OpSHA256 length limits to be exceeded if it were used
        # directly
        stamper = self.make_stamper("a52fe6e3d4b15057ff41df0509dd302bc5863c29")

        self.assertEqual(stamper.timestamp.msg,
                         b'\x1dW\x9c\xea\x94&`\xc2\xfb\xba \x19Q\x0f\xdb\xf0\x7f\x14\xe3\x14zb\t\xdb\xcf\xf93I\xe9h\xb9\x8d')
