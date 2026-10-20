import http.client
import logging
import os
import types
import unittest
from unittest import mock

import bitcoin.core
import bitcoin.rpc
import opentimestamps.calendar
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation, UnknownAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.timestamp import Timestamp
from otsclient.args import parse_ots_args
from otsclient.cache import TimestampCache
from otsclient.cmds import is_timestamp_complete, upgrade_timestamp, verify_timestamp


class FakeCache:
    def __getitem__(self, key):
        raise KeyError(key)

    def merge(self, stamp):
        pass


class FakeProxy:
    """Bitcoin node where only block 100 exists, with the given merkle root"""

    def __init__(self, merkleroot):
        self.merkleroot = merkleroot

    def getblockcount(self):
        return 100

    def getblockhash(self, height):
        if height > 100:
            raise IndexError('Block height out of range')
        return bytes([height]) * 32

    def getblockheader(self, blockhash):
        return bitcoin.core.CBlockHeader(hashMerkleRoot=self.merkleroot, nTime=1700000000)


def make_args(proxy, use_bitcoin=True):
    return types.SimpleNamespace(use_bitcoin=use_bitcoin,
                                 setup_bitcoin=lambda quiet=False: proxy,
                                 cache=FakeCache(),
                                 whitelist={'http://a.example'},
                                 calendar_urls=[],
                                 wait=False,
                                 timeout=5)


def bitcoin_stamp(height, msg=b'x'):
    """Timestamp with a Bitcoin attestation on SHA256(msg)"""
    stamp = Timestamp(msg)
    tip = stamp.ops.add(OpSHA256())
    tip.attestations.add(BitcoinBlockHeaderAttestation(height))
    return stamp, tip.msg


class TestIsTimestampComplete(unittest.TestCase):

    def test_attestation_matching_the_block(self):
        stamp, merkleroot = bitcoin_stamp(100)
        self.assertTrue(is_timestamp_complete(stamp, make_args(FakeProxy(merkleroot))))

    def test_attestation_not_matching_the_block(self):
        stamp, merkleroot = bitcoin_stamp(100)
        self.assertFalse(is_timestamp_complete(stamp, make_args(FakeProxy(b'\x01' * 32))))

    def test_attestation_for_missing_block(self):
        stamp, merkleroot = bitcoin_stamp(101)
        self.assertFalse(is_timestamp_complete(stamp, make_args(FakeProxy(merkleroot))))

    def test_attestation_for_height_the_node_cannot_parse(self):
        class StrictProxy(FakeProxy):
            def getblockhash(self, height):
                if height >= 2**31:
                    raise bitcoin.rpc.JSONRPCError({'code': -1, 'message': 'JSON integer out of range'})
                return super().getblockhash(height)

        for height in (2**31, 2**40):
            with self.subTest(height=height):
                stamp, merkleroot = bitcoin_stamp(height)
                self.assertFalse(is_timestamp_complete(stamp, make_args(StrictProxy(merkleroot))))

    def test_attestation_not_checkable_without_bitcoin(self):
        stamp, merkleroot = bitcoin_stamp(100)
        self.assertTrue(is_timestamp_complete(stamp, make_args(None, use_bitcoin=False)))

    def test_attestation_not_checkable_without_node_configuration(self):
        stamp, merkleroot = bitcoin_stamp(100)
        args = make_args(None)
        args.setup_bitcoin = mock.Mock(side_effect=SystemExit(1))
        self.assertTrue(is_timestamp_complete(stamp, args))

    def test_attestation_not_checkable_when_node_setup_raises(self):
        stamp, merkleroot = bitcoin_stamp(100)
        args = make_args(None)
        args.setup_bitcoin = mock.Mock(side_effect=ValueError('Cookie file unusable'))
        self.assertTrue(is_timestamp_complete(stamp, args))

    def check_node_error(self, error, method):
        stamp, merkleroot = bitcoin_stamp(100)
        proxy = FakeProxy(merkleroot)
        setattr(proxy, method, mock.Mock(side_effect=error))
        self.assertTrue(is_timestamp_complete(stamp, make_args(proxy)))

    def test_node_warming_up(self):
        self.check_node_error(bitcoin.rpc.JSONRPCError({'code': -28, 'message': 'Loading block index...'}),
                              'getblockcount')

    def test_node_rejects_credentials(self):
        self.check_node_error(bitcoin.rpc.JSONRPCError({'code': -342, 'message': 'non-JSON HTTP response with 401'}),
                              'getblockcount')

    def test_node_error_on_getblockheader(self):
        self.check_node_error(bitcoin.rpc.JSONRPCError({'code': -5, 'message': 'Block not found'}),
                              'getblockheader')

    def test_node_disconnects_on_getblockheader(self):
        self.check_node_error(ConnectionResetError('reset'), 'getblockheader')

    def test_failed_node_setup_tried_once(self):
        stamp, merkleroot = bitcoin_stamp(100)
        args = make_args(None)
        setup = mock.Mock(side_effect=ValueError('Cookie file unusable'))
        args.setup_bitcoin = setup
        self.assertTrue(is_timestamp_complete(stamp, args))
        self.assertTrue(is_timestamp_complete(stamp, args))
        self.assertEqual(setup.call_count, 1)

    def test_connection_error_does_not_break_verify(self):
        class DeadProxy:
            """Like python-bitcoinlib's Proxy: unusable after a refused connection"""
            refused = False

            def getblockcount(self):
                if self.refused:
                    raise http.client.CannotSendRequest('Request-sent')
                self.refused = True
                raise ConnectionRefusedError('refused')

        stamp, merkleroot = bitcoin_stamp(100)
        stamp.attestations.add(PendingAttestation('http://a.example'))
        args = make_args(None)
        args.setup_bitcoin = lambda quiet=False: DeadProxy()
        args.cache = TimestampCache(None)

        calendar = mock.Mock()
        calendar.get_timestamp.side_effect = opentimestamps.calendar.CommitmentNotFoundError('pending')
        with mock.patch('otsclient.cmds.remote_calendar', return_value=calendar):
            self.assertFalse(verify_timestamp(stamp, args))

    def test_pending_only(self):
        stamp = Timestamp(b'x')
        stamp.attestations.add(PendingAttestation('http://a.example'))
        self.assertFalse(is_timestamp_complete(stamp, make_args(FakeProxy(b'\x01' * 32))))


class TestNodeSetupLogging(unittest.TestCase):
    """With the real setup_bitcoin and a node URL that can't be used"""

    def setUp(self):
        self.args = parse_ots_args(['--no-cache', '--bitcoin-node', 'ftp://x', 'upgrade', os.devnull])
        for f in self.args.files:
            self.addCleanup(f.close)

    def test_upgrade_logs_no_error(self):
        stamp, merkleroot = bitcoin_stamp(100)
        with self.assertLogs(level=logging.DEBUG) as logs:
            self.assertTrue(is_timestamp_complete(stamp, self.args))
        self.assertEqual([r for r in logs.records if r.levelno >= logging.WARNING], [])
        self.assertTrue(any('Could not connect to Bitcoin node' in r.getMessage() for r in logs.records))

    def test_other_callers_still_log_an_error(self):
        with self.assertLogs(level=logging.ERROR) as logs, self.assertRaises(SystemExit):
            self.args.setup_bitcoin()
        self.assertIn('Could not connect to Bitcoin node', logs.output[0])


class TestUpgradeTimestamp(unittest.TestCase):

    def test_calendars_still_queried_after_refuted_attestation(self):
        stamp = Timestamp(b'x')
        pending = stamp.ops.add(OpSHA256())
        pending.attestations.add(PendingAttestation('http://a.example'))
        # A Bitcoin attestation that no block backs, as another calendar can return
        stamp.ops.add(OpSHA256()).attestations.add(BitcoinBlockHeaderAttestation(50))

        answer, merkleroot = bitcoin_stamp(100, msg=pending.msg)
        calendar = mock.Mock()
        calendar.get_timestamp.return_value = answer

        args = make_args(FakeProxy(merkleroot))
        with mock.patch('otsclient.cmds.remote_calendar', return_value=calendar):
            self.assertTrue(upgrade_timestamp(stamp, args))

        calendar.get_timestamp.assert_called_once()
        self.assertEqual(calendar.get_timestamp.call_args[0], (pending.msg,))
        self.assertTrue(is_timestamp_complete(stamp, args))

    def test_wait_with_nothing_pending_returns(self):
        stamp = Timestamp(b'x')
        stamp.ops.add(OpSHA256()).attestations.add(UnknownAttestation(b'\x01' * 8, b''))
        args = make_args(None)
        args.wait = True
        args.wait_interval = 30
        with mock.patch('otsclient.cmds.remote_calendar') as remote_calendar, \
                mock.patch('otsclient.cmds.time.sleep', side_effect=AssertionError('waited')):
            self.assertFalse(upgrade_timestamp(stamp, args))
        remote_calendar.assert_not_called()
