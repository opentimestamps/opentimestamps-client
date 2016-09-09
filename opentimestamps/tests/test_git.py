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
from opentimestamps.git import *

class Test_GitTreeTimestamper(unittest.TestCase):

    def setUp(self):
        self.db_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.db_dir.cleanup()
        del self.db_dir

    def make_stamper(self, commit):
        # Yes, we're using our own git repo as the test data!
        repo = git.Repo(__file__ + '../../../../')

        db = dbm.open(self.db_dir.name + '/db', 'c')
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

        self.assertEqual(stamper.timestamp.msg,
                         OpSHA256()(OpSHA256()(b'') + # file itself
                                    OpSHA256()(OpSHA256()(b'') + nonce_key))) # per-file nonce
        self.assertEqual(stamper.timestamp.msg, b'\xaa0\x13\xe4\xbe\xf2`)\x18\xbe\x8f;-_o\x90\xe3\xf6]\x16\xfeZH_"\xe8\x97\xdb\xf1\x92\xfa\x00')

    def test_two_file_tree(self):
        """Git tree with a two files"""
        stamper = self.make_stamper("78eb5cdc1ec638be72d6fb7a38c4d24f2be5d081")

        nonce_key = OpSHA256()(OpSHA256()(b'a\n') +
                               OpSHA256()(b'b\n') +
                               b'\x01\x89\x08\x0c\xfb\xd0\xe8\x08') # tag

        n_a = OpSHA256()(OpSHA256()(b'a\n') +
                         OpSHA256()(OpSHA256()(b'a\n') + nonce_key))
        n_b = OpSHA256()(OpSHA256()(b'b\n') +
                         OpSHA256()(OpSHA256()(b'b\n') + nonce_key))

        self.assertEqual(stamper.timestamp.msg,
                         OpSHA256()(n_a + n_b))
        self.assertEqual(stamper.timestamp.msg, b'<\xc8I\x1a\xfd\x81\xa6\x99\xbf\r\xf1\xe5\xba^:\xb4\x04\xf0\x89}^\xd1\x13S\xde\xf29\n\xb6\x15A\xb2')

    def test_tree_with_children(self):
        """Git tree with child trees"""
        stamper = self.make_stamper("b22192fffb9aad27eb57986e7fe89f8047340346")

        d_one = b'\xaa0\x13\xe4\xbe\xf2`)\x18\xbe\x8f;-_o\x90\xe3\xf6]\x16\xfeZH_"\xe8\x97\xdb\xf1\x92\xfa\x00'
        d_two = b'<\xc8I\x1a\xfd\x81\xa6\x99\xbf\r\xf1\xe5\xba^:\xb4\x04\xf0\x89}^\xd1\x13S\xde\xf29\n\xb6\x15A\xb2'

        nonce_key = OpSHA256()(d_one + d_two +
                               b'\x01\x89\x08\x0c\xfb\xd0\xe8\x08') # tag

        n_one = OpSHA256()(d_one + OpSHA256()(d_one + nonce_key))
        n_two = OpSHA256()(d_two + OpSHA256()(d_two + nonce_key))

        self.assertEqual(stamper.timestamp.msg,
                         OpSHA256()(n_one + n_two))
