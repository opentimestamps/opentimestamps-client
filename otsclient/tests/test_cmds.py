import unittest

from bitcoin.core import lx

from otsclient.cmds import get_waiting_tx_state


class FakeProxy(object):

    def __init__(self, responses):
        self.responses = responses

    def gettransaction(self, txid):
        return self.responses[txid]


class TestCmds(unittest.TestCase):

    def test_get_waiting_tx_state_returns_confirmed_tx(self):
        txid_hex = 'b663f1072fbb53cc4d986435a4d822df7a866ff44d8bcb0e9c2dd6bc212e776e'
        blockhash_hex = '11' * 32
        nonce = bytes.fromhex('a373af151062343e242b3e734dd77d0e')

        proxy = FakeProxy({
            lx(txid_hex): {
                'confirmations': 1,
                'blockhash': blockhash_hex,
            },
        })

        txid, blockhash = get_waiting_tx_state(proxy, lx(txid_hex), nonce)
        self.assertEqual(txid, lx(txid_hex))
        self.assertEqual(blockhash, lx(blockhash_hex))