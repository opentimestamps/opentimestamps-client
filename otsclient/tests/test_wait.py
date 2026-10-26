import os
import types
import unittest
from unittest import mock

from opentimestamps.core.notary import PendingAttestation, UnknownAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.timestamp import Timestamp
from otsclient.cmds import upgrade_timestamp


class FakeCache:
    def __getitem__(self, key):
        raise KeyError(key)

    def merge(self, stamp):
        pass


class Slept(Exception):
    pass


class TestWait(unittest.TestCase):

    def test_new_attestation_that_does_not_complete_waits_before_asking_again(self):
        stamp = Timestamp(b'x')
        pending = stamp.ops.add(OpSHA256())
        pending.attestations.add(PendingAttestation('http://a.example'))

        calls = []

        def get_timestamp(commitment, timeout=None):
            calls.append(commitment)
            if len(calls) > 3:
                raise RuntimeError('asked again without waiting')
            # A different attestation on every request
            answer = Timestamp(commitment)
            answer.ops.add(OpSHA256()).attestations.add(UnknownAttestation(b'\x01' * 8, os.urandom(8)))
            return answer

        calendar = mock.Mock()
        calendar.get_timestamp.side_effect = get_timestamp

        args = types.SimpleNamespace(use_bitcoin=False,
                                     cache=FakeCache(),
                                     whitelist={'http://a.example'},
                                     calendar_urls=[],
                                     wait=True,
                                     wait_interval=30,
                                     timeout=5)
        with mock.patch('otsclient.cmds.remote_calendar', return_value=calendar), \
                mock.patch('otsclient.cmds.time.sleep', side_effect=Slept):
            with self.assertRaises(Slept):
                upgrade_timestamp(stamp, args)

        self.assertEqual(len(calls), 1)
