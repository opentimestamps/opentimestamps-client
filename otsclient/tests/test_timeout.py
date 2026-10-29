import os
import socket
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

import opentimestamps.calendar
from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.timestamp import Timestamp
from otsclient.args import parse_ots_args
from otsclient.cmds import create_timestamp, upgrade_timestamp


class FakeCache:
    def __getitem__(self, key):
        raise KeyError(key)

    def merge(self, stamp):
        pass


class TestTimeout(unittest.TestCase):

    def test_upgrade_passes_timeout_to_calendar(self):
        stamp = Timestamp(b'x')
        stamp.ops.add(OpSHA256()).attestations.add(PendingAttestation('http://a.example'))

        calendar = mock.Mock()
        calendar.get_timestamp.side_effect = opentimestamps.calendar.CommitmentNotFoundError('pending')

        args = types.SimpleNamespace(use_bitcoin=False,
                                     cache=FakeCache(),
                                     whitelist={'http://a.example'},
                                     calendar_urls=[],
                                     wait=False,
                                     timeout=7)
        with mock.patch('otsclient.cmds.remote_calendar', return_value=calendar):
            upgrade_timestamp(stamp, args)

        calendar.get_timestamp.assert_called_once_with(mock.ANY, timeout=7)

    def test_upgrade_and_verify_take_timeout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'f.ots')
            with open(path, 'wb'):
                pass
            self.assertEqual(parse_ots_args(['--no-cache', 'upgrade', path]).timeout, 5)
            self.assertEqual(parse_ots_args(['--no-cache', 'upgrade', '--timeout', '2', path]).timeout, 2)
            self.assertEqual(parse_ots_args(['--no-cache', 'verify', path]).timeout, 5)
            self.assertEqual(parse_ots_args(['--no-cache', 'verify', '--timeout', '2', path]).timeout, 2)

    def test_calendar_sending_a_byte_at_a_time_is_cut_off(self):
        """The timeout is a total deadline, not only a limit on each read"""
        stop = threading.Event()
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)

        def trickle():
            conn, _ = server.accept()
            with conn:
                conn.recv(4096)
                response = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nxx'
                for i in range(len(response)):
                    if stop.wait(0.2):
                        return
                    try:
                        conn.sendall(response[i:i + 1])
                    except OSError:
                        return

        thread = threading.Thread(target=trickle, daemon=True)
        thread.start()

        url = 'http://127.0.0.1:%d' % server.getsockname()[1]
        stamp = Timestamp(b'x')
        stamp.ops.add(OpSHA256()).attestations.add(PendingAttestation(url))
        args = types.SimpleNamespace(use_bitcoin=False,
                                     cache=FakeCache(),
                                     whitelist={url},
                                     calendar_urls=[],
                                     wait=False,
                                     timeout=1)
        try:
            start = time.monotonic()
            upgrade_timestamp(stamp, args)
            elapsed = time.monotonic() - start
        finally:
            stop.set()
            server.close()

        self.assertLess(elapsed, 3)

    def test_stalling_calendar_is_not_asked_again_while_the_request_runs(self):
        release = threading.Event()
        requests = []

        def get_timestamp(commitment, timeout=None):
            requests.append(commitment)
            release.wait(30)
            raise opentimestamps.calendar.CommitmentNotFoundError('pending')

        calendar = mock.Mock(url='http://stalling.example')
        calendar.get_timestamp.side_effect = get_timestamp

        stamp = Timestamp(b'x')
        stamp.ops.add(OpSHA256()).attestations.add(PendingAttestation('http://stalling.example'))
        args = types.SimpleNamespace(use_bitcoin=False,
                                     cache=FakeCache(),
                                     whitelist={'http://stalling.example'},
                                     calendar_urls=[],
                                     wait=True,
                                     wait_interval=0,
                                     timeout=1)

        class Done(Exception):
            pass

        rounds = []

        def sleep(seconds):
            rounds.append(seconds)
            if len(rounds) == 3:
                raise Done

        try:
            with mock.patch('otsclient.cmds.remote_calendar', return_value=calendar), \
                    mock.patch('otsclient.cmds.time.sleep', sleep):
                with self.assertRaises(Done):
                    upgrade_timestamp(stamp, args)
        finally:
            release.set()

        self.assertEqual(len(requests), 1)

    def test_stamp_does_not_wait_for_a_slow_calendar_on_exit(self):
        release = threading.Event()
        submitting = []

        class Calendar:
            def __init__(self, url):
                self.url = url

            def submit(self, msg, timeout=None):
                if 'slow' in self.url:
                    submitting.append(threading.current_thread())
                    release.wait(30)
                stamp = Timestamp(msg)
                stamp.attestations.add(PendingAttestation(self.url))
                return stamp

        args = types.SimpleNamespace(use_btc_wallet=False, m=1, timeout=0.5)
        try:
            with mock.patch('otsclient.cmds.remote_calendar', Calendar):
                create_timestamp(Timestamp(b'x' * 32), ['http://fast.example', 'http://slow.example'], args)

            # The request is still running, and the interpreter does not wait for it at exit
            self.assertTrue(submitting[0].is_alive())
            self.assertTrue(submitting[0].daemon)
        finally:
            release.set()
