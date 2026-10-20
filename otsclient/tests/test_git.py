import io
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.op import OpSHA256, MsgValueError
from opentimestamps.core.timestamp import Timestamp
from otsclient.git import (hash_signed_commit, write_ascii_armored,
                           deserialize_ascii_armored_timestamp)

COMMIT = b'tree ' + b'0' * 40 + b'\n\nmessage\n'
PGP_SIG_1 = b'-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n'
PGP_SIG_2 = b'-----BEGIN PGP SIGNATURE-----\n\nBBBB\n-----END PGP SIGNATURE-----\n'


def armored_stamp(git_commit, covered_sig):
    stamp = Timestamp(hash_signed_commit(git_commit, covered_sig))
    stamp.attestations.add(PendingAttestation('http://127.0.0.1:1'))
    fd = io.BytesIO()
    write_ascii_armored(stamp, fd, 1)
    return fd.getvalue()


class TestGit(unittest.TestCase):

    def test_hash_signed_commit(self):
        def hash_signed_commit_old(git_commit, gpg_sig):
            return OpSHA256()(OpSHA256()(git_commit) + OpSHA256()(gpg_sig))
        for i in range(0, 1000):
            random_git_commit = os.urandom(i)
            random_gpg_sig = os.urandom(i)
            self.assertEqual(hash_signed_commit_old(random_git_commit, random_gpg_sig),
                             hash_signed_commit(random_git_commit, random_gpg_sig))

        self.assertEqual(hash_signed_commit_old(b'', b''), hash_signed_commit(b'', b''))

        self.assertRaises(MsgValueError, hash_signed_commit_old, b'0'*4097, b'')  # old version raises
        self.assertIsNotNone(hash_signed_commit(b'0'*4097, b''))  # new version does not

        self.assertTrue(True)

    def test_deserialize_ascii_armored_timestamp(self):
        sig = PGP_SIG_1 + armored_stamp(COMMIT, PGP_SIG_1)
        major, minor, stamp = deserialize_ascii_armored_timestamp(COMMIT, sig)
        self.assertEqual((major, minor), (1, 1))
        self.assertEqual(stamp.msg, hash_signed_commit(COMMIT, PGP_SIG_1))

    def test_deserialize_rejects_signature_after_timestamp(self):
        """The timestamp must cover the only PGP signature"""
        sig = PGP_SIG_1 + armored_stamp(COMMIT, PGP_SIG_1) + PGP_SIG_2
        self.assertEqual(deserialize_ascii_armored_timestamp(COMMIT, sig), (None, None, None))

    def test_deserialize_rejects_two_signatures(self):
        sig = PGP_SIG_1 + PGP_SIG_2
        sig += armored_stamp(COMMIT, sig)
        self.assertEqual(deserialize_ascii_armored_timestamp(COMMIT, sig), (None, None, None))

    def test_deserialize_rejects_two_timestamps(self):
        stamp = armored_stamp(COMMIT, PGP_SIG_1)
        sig = PGP_SIG_1 + stamp + stamp
        self.assertEqual(deserialize_ascii_armored_timestamp(COMMIT, sig), (None, None, None))

    def test_deserialize_rejects_non_signature_prefix(self):
        sig = b'junk\n' + PGP_SIG_1
        sig += armored_stamp(COMMIT, sig)
        self.assertEqual(deserialize_ascii_armored_timestamp(COMMIT, sig), (None, None, None))

    def run_wrapper_verify(self, sig):
        """Run the wrapper as git does to verify; return the signature GnuPG got"""
        with tempfile.TemporaryDirectory() as tmpdir:
            sig_path = os.path.join(tmpdir, 'sig')
            seen_path = os.path.join(tmpdir, 'seen')
            gpg_path = os.path.join(tmpdir, 'gpg')
            with open(sig_path, 'wb') as fd:
                fd.write(sig)
            with open(gpg_path, 'w') as fd:
                fd.write('#!/bin/sh\n'
                         'for a; do sig=$last; last=$a; done\n'
                         'cat "$sig" > "$SEEN_PATH"\n'
                         'cat > /dev/null\n')
            os.chmod(gpg_path, stat.S_IRWXU)

            argv = ['ots-git-gpg-wrapper', '--no-cache', '--no-default-whitelist', '--no-bitcoin',
                    '--gpg-program', gpg_path, '--', '--status-fd=1', '--verify', sig_path, '-']
            stdin = mock.Mock(buffer=io.BytesIO(COMMIT))
            with mock.patch.object(sys, 'argv', argv), \
                    mock.patch.object(sys, 'stdin', stdin), \
                    mock.patch.dict(os.environ, {'SEEN_PATH': seen_path}):
                from otsclient.git_gpg_wrapper import main
                try:
                    main()
                except SystemExit as exp:
                    self.assertEqual(exp.code, 0)
            with open(seen_path, 'rb') as fd:
                return fd.read()

    def test_wrapper_gives_gpg_the_covered_bytes(self):
        sig = PGP_SIG_1 + armored_stamp(COMMIT, PGP_SIG_1)
        self.assertEqual(self.run_wrapper_verify(sig), PGP_SIG_1)

    def test_wrapper_without_timestamp_passes_signature_unchanged(self):
        self.assertEqual(self.run_wrapper_verify(PGP_SIG_1), PGP_SIG_1)
