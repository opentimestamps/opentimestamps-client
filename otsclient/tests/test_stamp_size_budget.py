import io
import os
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import StreamDeserializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
from otsclient.cmds import merge_charging_root, stamp_command
from otsclient.git import deserialize_ascii_armored_timestamp

HOSTILE = 'http://hostile.example'
HONEST = 'http://honest.example'


def answer(msg, branches, attestation):
    t = Timestamp(msg)
    for i in range(branches):
        t.ops.add(OpAppend(i.to_bytes(3, 'big'))).attestations.add(attestation(i))
    return t


def hostile_answer(msg, attestation, charged=0):
    """An answer that fills the size limit left after charged"""
    node_usage = len(msg) + 3 + Timestamp.NODE_MEMORY_USAGE
    return answer(msg, (Timestamp.MAX_MEMORY_USAGE - charged) // node_usage, attestation)


def honest(uri):
    return lambda i: PendingAttestation(uri)


def fake_calendar(hostile_on):
    """Calendars of which HOSTILE answers a submission or an upgrade request
    (hostile_on is 'submit' or 'upgrade') with the most the tip can take"""
    def make(url):
        calendar = mock.Mock()

        def submit(msg, timeout=None):
            if url == HOSTILE and hostile_on == 'submit':
                return hostile_answer(msg, honest(HOSTILE))
            return answer(msg, 1, honest(HONEST))

        def get_timestamp(commitment, timeout=None):
            if url == HOSTILE:
                # The tip has the one answer to the submission
                return hostile_answer(commitment, lambda i: BitcoinBlockHeaderAttestation(1000 + i),
                                      len(commitment) + Timestamp.NODE_MEMORY_USAGE)
            return answer(commitment, 1, lambda i: BitcoinBlockHeaderAttestation(100))

        calendar.submit.side_effect = submit
        calendar.get_timestamp.side_effect = get_timestamp
        return calendar
    return make


class NoCache:
    def __getitem__(self, key):
        raise KeyError(key)

    def merge(self, stamp):
        pass


@unittest.skipUnless(hasattr(Timestamp, 'MAX_MEMORY_USAGE'), 'the library has no size limit')
class TestStampSizeBudget(unittest.TestCase):

    def test_merge_charges_the_dearest_root(self):
        shallow = Timestamp(b'')
        deep = Timestamp(b'')
        tip = deep.ops.add(OpAppend(b'a' * 100)).ops.add(OpAppend(b'b' * 100)).ops.add(OpSHA256())
        shallow.ops[OpAppend(b'c')] = tip
        other = hostile_answer(tip.msg, honest(HOSTILE), shallow._memory_usage())
        # The answer fits below the shallow root, and not below the deep one
        self.assertLessEqual(shallow._memory_usage() + other._memory_usage(), Timestamp.MAX_MEMORY_USAGE)
        self.assertGreater(deep._memory_usage() + other._memory_usage(), Timestamp.MAX_MEMORY_USAGE)

        for roots in ([shallow, deep], [deep, shallow]):
            with self.assertRaises(ValueError):
                merge_charging_root(tip, other, roots)
            self.assertEqual(len(tip.ops), 0)

    def stamp_three_files(self, hostile_on, wait):
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = []
            for name in ('a', 'b', 'c'):
                paths.append(os.path.join(tmpdir, name))
                with open(paths[-1], 'wb') as fd:
                    fd.write(name.encode())

            args = types.SimpleNamespace(
                files=[open(path, 'rb') for path in paths],
                calendar_urls=[HOSTILE, HONEST], use_btc_wallet=False, m=1, timeout=5,
                wait=wait, wait_interval=0, cache=NoCache(), use_bitcoin=False, whitelist=set())
            try:
                with mock.patch('otsclient.cmds.remote_calendar', side_effect=fake_calendar(hostile_on)):
                    stamp_command(args)
            finally:
                for fd in args.files:
                    fd.close()

            uris = []
            for path in paths:
                with open(path + '.ots', 'rb') as fd:
                    stamp = DetachedTimestampFile.deserialize(StreamDeserializationContext(fd))
                uris.append(stamp.timestamp.all_attestations())
            return [{a for _, a in attestations} for attestations in uris]

    def test_stamp_writes_what_it_can_read_back(self):
        for attestations in self.stamp_three_files('submit', wait=False):
            self.assertEqual(attestations, {PendingAttestation(HONEST)})

    def test_stamp_wait_writes_what_it_can_read_back(self):
        for attestations in self.stamp_three_files('upgrade', wait=True):
            self.assertEqual(attestations, {PendingAttestation(HONEST), BitcoinBlockHeaderAttestation(100)})

    def test_git_wrapper_writes_what_it_can_read_back(self):
        from otsclient.git_gpg_wrapper import main

        commit = None
        with tempfile.TemporaryDirectory() as tmpdir:
            def git(*cmd, **kwargs):
                return subprocess.run(('git',) + cmd, cwd=tmpdir, check=True, capture_output=True, **kwargs).stdout

            git('init', '-q')
            with open(os.path.join(tmpdir, 'file'), 'wb') as fd:
                fd.write(b'content')
            git('add', 'file')
            tree = git('write-tree').decode().strip()
            commit = b'tree ' + tree.encode() + b'\n\nmessage\n'

            pgp_sig = b'-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n'
            gpg_path = os.path.join(tmpdir, 'gpg')
            with open(gpg_path, 'w') as fd:
                fd.write("#!/bin/sh\ncat > /dev/null\nprintf '%s' '" + pgp_sig.decode() + "'\n")
            os.chmod(gpg_path, stat.S_IRWXU)

            argv = ['ots-git-gpg-wrapper', '--no-cache', '--no-default-whitelist', '--no-bitcoin',
                    '-m', '1', '-c', HOSTILE, '-c', HONEST,
                    '--gpg-program', gpg_path, '--', '-bsau', 'KEY']
            stdout = io.BytesIO()
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                with mock.patch.object(sys, 'argv', argv), \
                        mock.patch.object(sys, 'stdin', mock.Mock(buffer=io.BytesIO(commit))), \
                        mock.patch.object(sys, 'stdout', mock.Mock(buffer=stdout)), \
                        mock.patch('otsclient.cmds.remote_calendar', side_effect=fake_calendar('submit')):
                    main()
            finally:
                os.chdir(old_cwd)

        _, _, stamp = deserialize_ascii_armored_timestamp(commit, stdout.getvalue())
        self.assertIsNotNone(stamp, 'the timestamp that was written cannot be read back')
        self.assertEqual({a for _, a in stamp.all_attestations()}, {PendingAttestation(HONEST)})


class TestMergeChargingRoot(unittest.TestCase):

    def test_library_without_memory_usage_merges_without_a_root(self):
        class Node:
            def merge(self, other, *, root=None):
                self.root = root

        node = Node()
        merge_charging_root(node, object(), [object(), object()])
        self.assertIsNone(node.root)


@unittest.skipUnless(hasattr(Timestamp, 'MAX_MEMORY_USAGE'), 'the library has no size limit')
class TestGitExtractSizeBudget(unittest.TestCase):

    def extract(self, fill, joined=None):
        """Run git-extract for a file whose commit timestamp fills the limit down to fill nodes short

        Returns the exit status of git-extract, or None, and the .ots file that was written, or None.
        """
        from git import Repo
        from opentimestamps.core.git import GitTreeTimestamper
        from otsclient.cmds import git_extract_command

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = os.path.realpath(tmpdir)
            env = dict(os.environ, GIT_AUTHOR_NAME='a', GIT_AUTHOR_EMAIL='a@example.invalid',
                       GIT_COMMITTER_NAME='a', GIT_COMMITTER_EMAIL='a@example.invalid',
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)

            def git(*cmd):
                subprocess.run(('git',) + cmd, cwd=tmpdir, check=True, capture_output=True, env=env)

            git('init', '-q')
            os.mkdir(os.path.join(tmpdir, 'dir'))
            # A tree with one entry adds no op to the file's timestamp, so give the trees siblings
            for name in ('dir/file', 'dir/sibling', 'sibling'):
                with open(os.path.join(tmpdir, name), 'wb') as fd:
                    fd.write(name.encode())
            git('add', '.')
            git('-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'm')

            commit = Repo(tmpdir).commit('HEAD')
            tip = GitTreeTimestamper(commit.tree)['dir/file'].timestamp
            while tip.ops:
                tip = tuple(tip.ops.values())[0]

            # The commit timestamp has an OpAppend of the tree's digest first, and the answer below it
            commit_stamp = Timestamp(b'c' * 32)
            below = commit_stamp.ops.add(OpAppend(tip.msg if joined is None else joined))
            node_usage = len(below.msg) + 3 + Timestamp.NODE_MEMORY_USAGE
            budget = Timestamp.MAX_MEMORY_USAGE - commit_stamp._memory_usage()
            for i in range((budget // node_usage) - fill):
                below.ops.add(OpAppend(i.to_bytes(3, 'big'))).attestations.add(PendingAttestation(HOSTILE))
            self.assertLessEqual(commit_stamp._memory_usage(), Timestamp.MAX_MEMORY_USAGE)

            out = os.path.join(tmpdir, 'out.ots')
            args = types.SimpleNamespace(path=os.path.join(tmpdir, 'dir', 'file'), annex=False,
                                         timestamp_file=None, commit='HEAD')
            args.timestamp_file = open(out, 'xb')
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            status = None
            try:
                with mock.patch('otsclient.git.extract_sig_from_git_commit', return_value=(b'commit', b'sig')), \
                        mock.patch('otsclient.git.deserialize_ascii_armored_timestamp',
                                   return_value=(1, 1, commit_stamp)):
                    try:
                        git_extract_command(args)
                    except SystemExit as exp:
                        status = exp.code
            finally:
                os.chdir(old_cwd)
                args.timestamp_file.close()
            written = None
            if os.path.getsize(out):
                with open(out, 'rb') as fd:
                    written = DetachedTimestampFile.deserialize(StreamDeserializationContext(fd))
            return status, written

    def test_git_extract_refuses_a_commit_timestamp_that_does_not_fit(self):
        # The file's tree path uses more memory than the node's own share of what is left
        with self.assertLogs(level='ERROR') as logs:
            status, written = self.extract(fill=0)

        self.assertEqual(status, 1)
        self.assertIn('cannot be joined', logs.output[0])
        self.assertIn('limit', logs.output[0])
        self.assertIsNone(written)

    def test_git_extract_refuses_a_commit_timestamp_for_another_tree(self):
        with self.assertLogs(level='ERROR') as logs:
            status, written = self.extract(fill=20, joined=b'another tree')

        self.assertEqual(status, 1)
        self.assertIn('cannot be joined', logs.output[0])
        self.assertIsNone(written)

    def test_git_extract_writes_what_it_can_read_back(self):
        status, written = self.extract(fill=20)

        self.assertIsNone(status)
        self.assertIn(PendingAttestation(HOSTILE), {a for _, a in written.timestamp.all_attestations()})
