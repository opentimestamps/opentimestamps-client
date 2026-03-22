import json
import tempfile
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

    def test_get_waiting_tx_state_tracks_directional_replacement(self):
        old_txid_hex = '00aa848f0e6a36deb38ed180391cc079ed75a2986ad90c152e628646b6842512'
        new_txid_hex = 'b663f1072fbb53cc4d986435a4d822df7a866ff44d8bcb0e9c2dd6bc212e776e'
        nonce = bytes.fromhex('a373af151062343e242b3e734dd77d0e')

        proxy = FakeProxy({
            lx(old_txid_hex): {
                'confirmations': 0,
                'walletconflicts': [new_txid_hex],
                'replaced_by_txid': new_txid_hex,
            },
            lx(new_txid_hex): {
                'confirmations': 0,
                'walletconflicts': [old_txid_hex],
                'replaces_txid': old_txid_hex,
            },
        })

        with tempfile.TemporaryDirectory() as temp_dir:
            pending_path = temp_dir + '/stamp.ots.pending'

            txid, blockhash = get_waiting_tx_state(proxy, lx(old_txid_hex), nonce, pending_path)
            self.assertEqual(txid, lx(new_txid_hex))
            self.assertIsNone(blockhash)

            with open(pending_path, 'r') as f:
                pending = json.load(f)
            self.assertEqual(pending, {'nonce': nonce.hex(), 'txid': new_txid_hex})

            txid, blockhash = get_waiting_tx_state(proxy, txid, nonce, pending_path)
            self.assertEqual(txid, lx(new_txid_hex))
            self.assertIsNone(blockhash)

    def test_get_waiting_tx_state_tracks_confirmed_replacement(self):
        old_txid_hex = '00aa848f0e6a36deb38ed180391cc079ed75a2986ad90c152e628646b6842512'
        new_txid_hex = 'b663f1072fbb53cc4d986435a4d822df7a866ff44d8bcb0e9c2dd6bc212e776e'
        blockhash_hex = '11' * 32
        nonce = bytes.fromhex('a373af151062343e242b3e734dd77d0e')

        proxy = FakeProxy({
            lx(old_txid_hex): {
                'confirmations': -1,
                'walletconflicts': [new_txid_hex],
                'replaced_by_txid': new_txid_hex,
            },
            lx(new_txid_hex): {
                'confirmations': 1,
                'walletconflicts': [old_txid_hex],
                'replaces_txid': old_txid_hex,
                'blockhash': blockhash_hex,
            },
        })

        txid, blockhash = get_waiting_tx_state(proxy, lx(old_txid_hex), nonce)
        self.assertEqual(txid, lx(new_txid_hex))
        self.assertEqual(blockhash, lx(blockhash_hex))