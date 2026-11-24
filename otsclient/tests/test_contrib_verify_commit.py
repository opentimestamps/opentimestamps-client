# Copyright (C) 2026 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import importlib.machinery
import importlib.util
import os
import unittest

# The contrib script has no .py extension; load it via SourceFileLoader.
SCRIPT_PATH = os.path.join(os.path.dirname(__file__),
                           '..', '..', 'contrib', 'ots-git-verify-commit')


def load_script():
    loader = importlib.machinery.SourceFileLoader('otsgvc', SCRIPT_PATH)
    spec = importlib.util.spec_from_loader('otsgvc', loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def make_commit(gpgsig_lines=None):
    lines = [b"tree 0000000000000000000000000000000000000000",
             b"author A <a@a> 1 +0000",
             b"committer A <a@a> 1 +0000"]
    if gpgsig_lines is not None:
        lines.append(b"gpgsig " + gpgsig_lines[0])
        lines.extend(b" " + line for line in gpgsig_lines[1:])
    lines.extend([b"", b"msg", b""])
    return b"\n".join(lines)


class Test_load_timestamp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_script()

    def test_unsigned_commit(self):
        raw = make_commit()
        _, _, _, err, code = self.mod.load_timestamp(raw)
        self.assertEqual(code, self.mod.EXIT_ERROR)
        self.assertIn('no GPG signature', err)

    def test_signed_no_ots(self):
        raw = make_commit([
            b"-----BEGIN PGP SIGNATURE-----",
            b"",
            b"fakebase64==",
            b"-----END PGP SIGNATURE-----",
        ])
        _, _, _, err, code = self.mod.load_timestamp(raw)
        self.assertEqual(code, self.mod.EXIT_NO_OTS)
        self.assertIn('no OpenTimestamps data', err)

    def test_signed_corrupt_ots(self):
        # OTS armor header present but garbage payload: must be an error
        # (exit 1), not "no OTS data" (exit 3).
        raw = make_commit([
            b"-----BEGIN PGP SIGNATURE-----",
            b"",
            b"fakebase64==",
            b"-----END PGP SIGNATURE-----",
            b"-----BEGIN OPENTIMESTAMPS GIT TIMESTAMP-----",
            b"",
            b"!!!not-base64!!!",
            b"-----END OPENTIMESTAMPS GIT TIMESTAMP-----",
        ])
        _, _, _, err, code = self.mod.load_timestamp(raw)
        self.assertEqual(code, self.mod.EXIT_ERROR)
        self.assertIn('corrupt', err)
