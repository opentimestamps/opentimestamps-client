# Copyright (C) 2018 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import unittest
from opentimestamps.core.timestamp import Timestamp
from opentimestamps.core.op import OpAppend
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, LitecoinBlockHeaderAttestation, \
    PendingAttestation, UnknownAttestation
from otsclient.cmds import discard_attestations, discard_suboptimal, prune_tree, prune_timestamp


class TestPrune(unittest.TestCase):

    def test_discard_attestations(self):
        """Discarding attestations"""
        t = Timestamp(b'')
        t1 = t.ops.add(OpAppend(b'\x01'))
        t2 = t.ops.add(OpAppend(b'\x02'))
        t.attestations = {UnknownAttestation(b'unknown.', b'')}
        t1.attestations = {BitcoinBlockHeaderAttestation(1)}
        t2.attestations = {PendingAttestation("c2"), PendingAttestation("c1")}

        discard_attestations(t, [UnknownAttestation, PendingAttestation("c1")])

        tn = Timestamp(b'')
        tn1 = tn.ops.add(OpAppend(b'\x01'))
        tn2 = tn.ops.add(OpAppend(b'\x02'))
        tn1.attestations = {BitcoinBlockHeaderAttestation(1)}
        tn2.attestations = {PendingAttestation("c2")}

        self.assertEqual(t, tn)

    def test_discard_suboptimal(self):
        """Discarding suboptimal attestations"""
        t = Timestamp(b'')
        t1 = t.ops.add(OpAppend(b'\x01'))
        t2 = t.ops.add(OpAppend(b'\x02'))
        t3 = t.ops.add(OpAppend(b'\x03\03'))
        t4 = t.ops.add(OpAppend(b'\x04'))
        t1.attestations = {BitcoinBlockHeaderAttestation(2)}
        t2.attestations = {BitcoinBlockHeaderAttestation(1)}
        t3.attestations = {LitecoinBlockHeaderAttestation(1)}
        t4.attestations = {LitecoinBlockHeaderAttestation(1)}

        discard_suboptimal(t, BitcoinBlockHeaderAttestation)
        discard_suboptimal(t, LitecoinBlockHeaderAttestation)

        tn = Timestamp(b'')
        tn1 = tn.ops.add(OpAppend(b'\x01'))
        tn2 = tn.ops.add(OpAppend(b'\x02'))
        tn3 = tn.ops.add(OpAppend(b'\x03\03'))
        tn4 = tn.ops.add(OpAppend(b'\x04'))
        tn2.attestations = {BitcoinBlockHeaderAttestation(1)}
        tn4.attestations = {LitecoinBlockHeaderAttestation(1)}

        self.assertEqual(t, tn)

    def test_prune_tree(self):
        """Pruning tree"""
        t = Timestamp(b'')

        empty, changed = prune_tree(t)

        self.assertTrue(empty)
        self.assertFalse(changed)

        t1 = t.ops.add(OpAppend(b'\x01'))
        t2 = t.ops.add(OpAppend(b'\x02'))
        t1.attestations = {PendingAttestation("c")}

        empty, changed = prune_tree(t)

        tn = Timestamp(b'')
        tn1 = tn.ops.add(OpAppend(b'\x01'))
        tn1.attestations = {PendingAttestation("c")}

        self.assertEqual(t, tn)
        self.assertFalse(empty)
        self.assertTrue(changed)

        _, changed = prune_tree(t)

        self.assertFalse(changed)

    def test_pruning_timestamp(self):
        """Pruning timestamp"""
        t = Timestamp(b'')
        t1 = t.ops.add(OpAppend(b'\x01'))
        t2 = t.ops.add(OpAppend(b'\x02'))
        t3 = t.ops.add(OpAppend(b'\x03'))
        t21 = t2.ops.add(OpAppend(b'\x02'))
        t31 = t3.ops.add(OpAppend(b'\x03'))
        t1.attestations = {PendingAttestation("c1")}
        t2.attestations = {PendingAttestation("c2")}
        t3.attestations = {PendingAttestation("c3")}
        t21.attestations = {BitcoinBlockHeaderAttestation(2)}
        t31.attestations = {BitcoinBlockHeaderAttestation(1)}

        prune_timestamp(t, [], [PendingAttestation], None)

        tn = Timestamp(b'')
        tn3 = tn.ops.add(OpAppend(b'\x03'))
        tn31 = tn3.ops.add(OpAppend(b'\x03'))
        tn31.attestations = {BitcoinBlockHeaderAttestation(1)}

        self.assertEqual(t, tn)
