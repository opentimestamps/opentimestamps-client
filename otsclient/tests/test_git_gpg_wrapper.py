import io
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

from otsclient.git_gpg_wrapper import main

COMMIT = b'tree ' + b'0' * 40 + b'\n\nmessage\n'
PGP_SIG = b'-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n'


class TestGitGpgWrapper(unittest.TestCase):

    def run_wrapper(self, gpg_script, gpg_args):
        """Run the wrapper with a fake GnuPG; return the exit status"""
        with tempfile.TemporaryDirectory() as tmpdir:
            sig_path = os.path.join(tmpdir, 'sig')
            gpg_path = os.path.join(tmpdir, 'gpg')
            with open(sig_path, 'wb') as fd:
                fd.write(PGP_SIG)
            with open(gpg_path, 'w') as fd:
                fd.write('#!/bin/sh\ncat > /dev/null\n' + gpg_script)
            os.chmod(gpg_path, stat.S_IRWXU)

            argv = ['ots-git-gpg-wrapper', '--no-cache', '--no-default-whitelist', '--no-bitcoin',
                    '--gpg-program', gpg_path, '--'] + [sig_path if a == 'SIG' else a for a in gpg_args]
            stdin = mock.Mock(buffer=io.BytesIO(COMMIT))
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(sys, 'stdin', stdin):
                try:
                    main()
                except SystemExit as exp:
                    return exp.code
                return 0

    def test_verify_returns_gpg_exit_status(self):
        script = 'echo "[GNUPG:] GOODSIG 0123456789ABCDEF Someone"\nexit 2\n'
        self.assertEqual(self.run_wrapper(script, ['--status-fd=1', '--verify', 'SIG', '-']), 2)

    def test_verify_returns_zero_when_gpg_succeeds(self):
        script = 'echo "[GNUPG:] GOODSIG 0123456789ABCDEF Someone"\nexit 0\n'
        self.assertEqual(self.run_wrapper(script, ['--status-fd=1', '--verify', 'SIG', '-']), 0)

    def test_sign_returns_gpg_exit_status(self):
        script = 'printf "%s" "-----BEGIN PGP SIGNATURE-----"\nexit 3\n'
        self.assertEqual(self.run_wrapper(script, ['--status-fd=2', '-bsau', 'KEY']), 3)
