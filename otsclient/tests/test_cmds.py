# Copyright (C) 2026 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import types
import unittest
from unittest.mock import Mock

from opentimestamps.core.timestamp import Timestamp
from opentimestamps.core.op import OpAppend
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation

from otsclient.cache import TimestampCache
from otsclient.cmds import verify_timestamp


class TestVerifyTimestampBitcoinUnreachable(unittest.TestCase):
    """verify_timestamp() must not let a Bitcoin RPC connection failure abort the
    process; the git gpg wrapper relies on it always returning so it can still
    invoke gpg regardless of the OTS verification outcome."""

    def _make_timestamp(self, heights):
        t = Timestamp(b'\x00' * 32)
        for i, height in enumerate(heights):
            sub = t.ops.add(OpAppend(bytes([i])))
            sub.attestations = {BitcoinBlockHeaderAttestation(height)}
        return t

    def _make_args(self, setup_bitcoin):
        return types.SimpleNamespace(
            calendar_urls=[],
            cache=TimestampCache(None),
            wait=False,
            use_bitcoin=True,
            setup_bitcoin=setup_bitcoin,
        )

    def test_unreachable_bitcoin_node_does_not_raise(self):
        t = self._make_timestamp([100])
        setup_bitcoin = Mock(side_effect=Exception("Cookie file unusable"))
        args = self._make_args(setup_bitcoin)

        good = verify_timestamp(t, args)

        self.assertFalse(good)

    def test_unreachable_bitcoin_node_calls_setup_bitcoin_once(self):
        t = self._make_timestamp([100, 200, 300])
        setup_bitcoin = Mock(side_effect=Exception("Cookie file unusable"))
        args = self._make_args(setup_bitcoin)

        good = verify_timestamp(t, args)

        self.assertFalse(good)
        self.assertEqual(setup_bitcoin.call_count, 1)

    def test_bitcoin_node_disconnect_mid_rpc_calls_getblockcount_once(self):
        t = self._make_timestamp([100, 200, 300])
        proxy = Mock()
        proxy.getblockcount = Mock(side_effect=ConnectionError("Connection reset"))
        setup_bitcoin = Mock(return_value=proxy)
        args = self._make_args(setup_bitcoin)

        good = verify_timestamp(t, args)

        self.assertFalse(good)
        self.assertEqual(setup_bitcoin.call_count, 1)
        self.assertEqual(proxy.getblockcount.call_count, 1)
