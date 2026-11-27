import http.client
import io
import os
import socket
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

import opentimestamps.calendar
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import DeserializationError
from opentimestamps.core.timestamp import Timestamp
from otsclient.cmds import upgrade_timestamp


class FakeCache:
    def __init__(self, stamp):
        self.stamp = stamp
        self.attestations_when_merged = None

    def __getitem__(self, key):
        raise KeyError(key)

    def merge(self, stamp):
        self.attestations_when_merged = {a for _, a in self.stamp.all_attestations()}


def make_args(stamp):
    return types.SimpleNamespace(use_bitcoin=False,
                                 cache=FakeCache(stamp),
                                 whitelist=set(),
                                 calendar_urls=['http://bad.example', 'http://good.example'],
                                 wait=False,
                                 timeout=5)


def pending_stamp():
    stamp = Timestamp(b'x')
    tip = stamp.ops.add(OpSHA256())
    tip.attestations.add(PendingAttestation('http://a.example'))
    return stamp, tip


class TestCalendarErrors(unittest.TestCase):

    def upgrade(self, stamp, answers):
        calendar = mock.Mock()
        calendar.get_timestamp.side_effect = answers
        args = make_args(stamp)
        with mock.patch('otsclient.cmds.remote_calendar', return_value=calendar):
            changed = upgrade_timestamp(stamp, args)
        return changed, args

    def test_failing_calendar_does_not_stop_the_others(self):
        errors = [DeserializationError('bad'),
                  http.client.RemoteDisconnected('closed'),
                  socket.timeout('timed out'),
                  http.client.InvalidURL('bad url'),
                  Exception('Unknown response from calendar: 500')]
        for error in errors:
            with self.subTest(error=error):
                stamp, tip = pending_stamp()
                answer = Timestamp(tip.msg)
                answer.ops.add(OpSHA256()).attestations.add(BitcoinBlockHeaderAttestation(100))

                changed, args = self.upgrade(stamp, [error, answer])

                self.assertTrue(changed)
                self.assertIn(BitcoinBlockHeaderAttestation(100), {a for _, a in stamp.all_attestations()})

    def test_attestation_on_the_commitment_itself(self):
        stamp, tip = pending_stamp()
        answer = Timestamp(tip.msg)
        answer.attestations.add(BitcoinBlockHeaderAttestation(100))

        changed, args = self.upgrade(stamp, [opentimestamps.calendar.CommitmentNotFoundError('pending'), answer])

        self.assertTrue(changed)
        self.assertIn(BitcoinBlockHeaderAttestation(100), tip.attestations)

    def test_cache_written_after_the_merge(self):
        stamp, tip = pending_stamp()
        answer = Timestamp(tip.msg)
        answer.ops.add(OpSHA256()).attestations.add(BitcoinBlockHeaderAttestation(100))

        changed, args = self.upgrade(stamp, [opentimestamps.calendar.CommitmentNotFoundError('pending'), answer])

        self.assertIn(BitcoinBlockHeaderAttestation(100), args.cache.attestations_when_merged)

    def upgrade_with_refused_merge(self, refuse):
        """Upgrade with two calendars, the first one's answer being refused"""
        stamp, tip = pending_stamp()
        refused = Timestamp(tip.msg)
        refused.ops.add(OpSHA256()).attestations.add(PendingAttestation('http://refused.example'))
        honest = Timestamp(tip.msg)
        honest.ops.add(OpSHA256()).attestations.add(BitcoinBlockHeaderAttestation(100))

        calendar = mock.Mock()
        calendar.get_timestamp.side_effect = [refused, honest]
        args = make_args(stamp)
        refuse(args)

        original_merge = Timestamp.merge

        def merge(self, other, **kwargs):
            if other is refused:
                raise ValueError('Merged timestamp op results exceed the size limit')
            return original_merge(self, other, **kwargs)

        with mock.patch('otsclient.cmds.remote_calendar', return_value=calendar), \
                mock.patch.object(Timestamp, 'merge', merge), \
                self.assertLogs(level='WARNING') as logs:
            changed = upgrade_timestamp(stamp, args)

        return stamp, changed, args, logs.output

    def test_refused_merge_skips_that_calendar(self):
        stamp, changed, args, logs = self.upgrade_with_refused_merge(lambda args: None)

        self.assertTrue(changed)
        self.assertEqual({a for _, a in stamp.all_attestations()},
                         {PendingAttestation('http://a.example'), BitcoinBlockHeaderAttestation(100)})
        self.assertTrue(any('size limit' in line and 'http://bad.example' in line for line in logs))

    def test_refused_cache_merge_keeps_the_upgrade(self):
        def refuse(args):
            def merge(stamp):
                if any(isinstance(a, BitcoinBlockHeaderAttestation) for _, a in stamp.all_attestations()):
                    raise ValueError('Merged timestamp op results exceed the size limit')
            args.cache.merge = merge

        stamp, changed, args, logs = self.upgrade_with_refused_merge(refuse)

        self.assertIn(BitcoinBlockHeaderAttestation(100), {a for _, a in stamp.all_attestations()})
        self.assertTrue(any('not cached' in line for line in logs))

    def test_refused_merge_from_the_cache_is_skipped(self):
        stamp, tip = pending_stamp()
        cached = Timestamp(tip.msg)
        cached.ops.add(OpSHA256()).attestations.add(BitcoinBlockHeaderAttestation(100))

        args = make_args(stamp)

        class CachedFake(FakeCache):
            def __getitem__(self, key):
                return cached

        args.cache = CachedFake(stamp)

        def merge(self, other, **kwargs):
            raise ValueError('Merged timestamp op results exceed the size limit')

        calendar = mock.Mock()
        calendar.get_timestamp.side_effect = opentimestamps.calendar.CommitmentNotFoundError('pending')
        with mock.patch('otsclient.cmds.remote_calendar', return_value=calendar), \
                mock.patch.object(Timestamp, 'merge', merge), \
                self.assertLogs(level='WARNING') as logs:
            upgrade_timestamp(stamp, args)

        self.assertTrue(any('Cache' in line and 'size limit' in line for line in logs.output))

    def test_merge_charges_the_whole_timestamp(self):
        stamp, tip = pending_stamp()
        answer = Timestamp(tip.msg)
        answer.ops.add(OpSHA256()).attestations.add(BitcoinBlockHeaderAttestation(100))
        calendar = mock.Mock()
        calendar.get_timestamp.return_value = answer
        roots = []

        def merge(self, other, *, root=None):
            roots.append(root)

        with mock.patch('otsclient.cmds.remote_calendar', return_value=calendar), \
                mock.patch.object(Timestamp, 'merge', merge):
            upgrade_timestamp(stamp, make_args(stamp))

        self.assertTrue(roots)
        self.assertTrue(all(root is stamp for root in roots))

    def test_wrapper_runs_gpg_when_timestamp_verification_fails(self):
        from otsclient.git_gpg_wrapper import main
        from otsclient.git import hash_signed_commit, write_ascii_armored

        commit = b'tree ' + b'0' * 40 + b'\n\nmessage\n'
        pgp_sig = b'-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n'
        stamp = Timestamp(hash_signed_commit(commit, pgp_sig))
        stamp.attestations.add(PendingAttestation('http://a.example'))
        armor = io.BytesIO()
        write_ascii_armored(stamp, armor, 1)

        with tempfile.TemporaryDirectory() as tmpdir:
            sig_path = os.path.join(tmpdir, 'sig')
            ran_path = os.path.join(tmpdir, 'ran')
            gpg_path = os.path.join(tmpdir, 'gpg')
            with open(sig_path, 'wb') as fd:
                fd.write(pgp_sig + armor.getvalue())
            with open(gpg_path, 'w') as fd:
                fd.write('#!/bin/sh\ncat > /dev/null\ntouch "$RAN_PATH"\n')
            os.chmod(gpg_path, stat.S_IRWXU)

            argv = ['ots-git-gpg-wrapper', '--no-cache', '--no-default-whitelist', '--no-bitcoin',
                    '--gpg-program', gpg_path, '--', '--status-fd=1', '--verify', sig_path, '-']
            with mock.patch.object(sys, 'argv', argv), \
                    mock.patch.object(sys, 'stdin', mock.Mock(buffer=io.BytesIO(commit))), \
                    mock.patch.dict(os.environ, {'RAN_PATH': ran_path}), \
                    mock.patch('otsclient.cmds.verify_timestamp', side_effect=Exception('boom')):
                try:
                    main()
                except SystemExit as exp:
                    self.assertEqual(exp.code, 0)

            self.assertTrue(os.path.exists(ran_path))

    def test_wrapper_runs_gpg_without_a_bitcoin_node(self):
        from otsclient.git_gpg_wrapper import main
        from otsclient.git import hash_signed_commit, write_ascii_armored

        commit = b'tree ' + b'0' * 40 + b'\n\nmessage\n'
        pgp_sig = b'-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n'
        stamp = Timestamp(hash_signed_commit(commit, pgp_sig))
        stamp.attestations.add(BitcoinBlockHeaderAttestation(100))
        armor = io.BytesIO()
        write_ascii_armored(stamp, armor, 1)

        with tempfile.TemporaryDirectory() as tmpdir:
            sig_path = os.path.join(tmpdir, 'sig')
            ran_path = os.path.join(tmpdir, 'ran')
            gpg_path = os.path.join(tmpdir, 'gpg')
            with open(sig_path, 'wb') as fd:
                fd.write(pgp_sig + armor.getvalue())
            with open(gpg_path, 'w') as fd:
                fd.write('#!/bin/sh\ncat > /dev/null\ntouch "$RAN_PATH"\n')
            os.chmod(gpg_path, stat.S_IRWXU)

            # An empty home has no Bitcoin configuration
            argv = ['ots-git-gpg-wrapper', '--no-cache', '--no-default-whitelist',
                    '--gpg-program', gpg_path, '--', '--status-fd=1', '--verify', sig_path, '-']
            with mock.patch.object(sys, 'argv', argv), \
                    mock.patch.object(sys, 'stdin', mock.Mock(buffer=io.BytesIO(commit))), \
                    mock.patch.dict(os.environ, {'RAN_PATH': ran_path, 'HOME': tmpdir}):
                try:
                    main()
                except SystemExit as exp:
                    self.assertEqual(exp.code, 0)

            self.assertTrue(os.path.exists(ran_path))
