# Copyright (C) 2012 Peter Todd <pete@petertodd.org>
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

from ...notary.bitcoin import BitcoinSignature, BITCOIN_TIMESTAMP_OFFSET
from ... import client

from opentimestamps._internal import unhexlify

class TestBitcoinNotary(unittest.TestCase):
    def test_verify(self):
        digest = unhexlify('020000004f43106852f5fc9264bab0a797350640d7c3ed6eb6c7ac7747010000000000004b7cd1551c43bb02d8465d5f167fd21bcaaf90720bc442439e1a633694618786c19cc450eae0041acee1e535')

        context = client.Context()
        class MockRPCProxy:
            def getblock(self2,block_hash):
                self.assertEqual(block_hash,'00000000000001f1732f7047b2cfc2aa2f898eb97f42d9f853643fc2636fa842')
                return dict(
                        hash = '00000000000001f1732f7047b2cfc2aa2f898eb97f42d9f853643fc2636fa842',
                        confirmations = 1000,
                        size = 289417,
                        height = 211520,
                        version = 2,
                        merkleroot = '8687619436631a9e4342c40b7290afca1bd27f165f5d46d802bb431c55d17c4b',
                        tx = [],
                        time = 1355062465,
                        nonce = 904257998,
                        bits = '1a04e0ea',
                        difficulty = 3438908.96015914,
                        previousblockhash = '000000000000014777acc7b66eedc3d740063597a7b0ba6492fcf5526810434f',
                        nextblockhash = '00000000000002de7366cd73b5ce18ff3d64bb04188fe973a27034e9448ac557')

        context.bitcoin_proxy = dict(mainnet = MockRPCProxy())

        sig = BitcoinSignature(digest=digest, identity='mainnet')

        self.assertEqual(sig.timestamp, 1355062465 + BITCOIN_TIMESTAMP_OFFSET)
        self.assertTrue(sig.validate(context=context))

        # FIXME: need tests for validation failure scenarios
