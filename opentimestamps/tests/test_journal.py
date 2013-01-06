# Copyright (C) 2012-2013 Peter Todd <pete@petertodd.org>
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution and at http://opentimestamps.org
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import unittest

import tempfile
import os
import shutil
import hashlib
import uuid

from opentimestamps.dag import *

from opentimestamps.journal import *

class _JournalTester:
    def test_connectivity(self, n=17):
        journal = self.journal_instantiator()

        digests = [b'unique prefix' + bytes([n]) for n in range(0, n)]

        closures = []
        digest_paths = []
        for digest in digests:
            self.assertNotIn(digest, journal.digests)

            digest_path = journal.add(digest)

            self.assertEqual(digest, digest_path[0])
            self.assertTrue(valid_path(digest, digest_path[1:]))
            self.assertIn(digest_path[-1], journal.digests)

            digest_paths.append(digest_path)

            closures.append(journal.closure())

        for (n, digest_path) in enumerate(digest_paths):
            digest = digest_path[-1]
            # Check that every closure created after that digest was added is
            # reachable.
            for closure in closures[n:]:
                path = journal.path(digest, closure)
                self.assertTrue(path is not None)
                if path:
                    self.assertEqual(path[-1], closure)
                self.assertTrue(valid_path(digest, path))

            # Check that every closure created before the digest
            # was added is *not* reachable.
            for closure in closures[0:n]:
                self.assertEqual(journal.path(digest, closure), None)


class TestLinearJournal(_JournalTester, unittest.TestCase):
    journal_instantiator = LinearJournal


class TestMerkleJournal(_JournalTester, unittest.TestCase):
    journal_instantiator = MerkleJournal

    def test_height_at_idx(self):
        self.assertSequenceEqual(
                (0,0,1,0,0,1,2,0,0,1,0,0,1,2,3,0,0,1,0,0,1,2,0,0,1,0,0,1,2,3,4),
                [MerkleJournal.height_at_idx(i) for i in range(0,31)])

    def test_get_mountain_peak_indexes(self):
        # 0,0,1,0,0,1,2,0,0,1,0,0,1,2,3,0,0,1,0,0,1,2,0,0,1,0,0,1,2,3,4
        self.assertSequenceEqual(
                MerkleJournal.get_mountain_peak_indexes(1),
                (0,))
        self.assertSequenceEqual(
                MerkleJournal.get_mountain_peak_indexes(2),
                (1,0))
        self.assertSequenceEqual(
                MerkleJournal.get_mountain_peak_indexes(3),
                (2,))
        self.assertSequenceEqual(
                MerkleJournal.get_mountain_peak_indexes(4),
                (3,2))
        self.assertSequenceEqual(
                MerkleJournal.get_mountain_peak_indexes(5),
                (4,3,2))
        self.assertSequenceEqual(
                MerkleJournal.get_mountain_peak_indexes(6),
                (5,2))
        self.assertSequenceEqual(
                MerkleJournal.get_mountain_peak_indexes(7),
                (6,))
        self.assertSequenceEqual(
                MerkleJournal.get_mountain_peak_indexes(30),
                (29,14))
        self.assertSequenceEqual(
                MerkleJournal.get_mountain_peak_indexes(31),
                (30,))


    def test_peak_child(self):
        # 0,0,1,0,0,1,2,0,0,1,0,0,1,2,3,0,0,1,0,0,1,2,0,0,1,0,0,1,2,3,4
        self.assertEqual(MerkleJournal.peak_child( 0), 2) # height 0, peak  0
        self.assertEqual(MerkleJournal.peak_child( 1), 2) # height 0, peak  1
        self.assertEqual(MerkleJournal.peak_child( 2), 6) # height 1, peak  0
        self.assertEqual(MerkleJournal.peak_child( 3), 5) # height 0, peak  2
        self.assertEqual(MerkleJournal.peak_child( 4), 5) # height 0, peak  3
        self.assertEqual(MerkleJournal.peak_child( 5), 6) # height 1, peak  1
        self.assertEqual(MerkleJournal.peak_child( 7), 9) # height 0, peak  4
        self.assertEqual(MerkleJournal.peak_child( 8), 9) # height 0, peak  5
        self.assertEqual(MerkleJournal.peak_child( 9),13) # height 1, peak  2
        self.assertEqual(MerkleJournal.peak_child(14),30) # height 3, peak  0
