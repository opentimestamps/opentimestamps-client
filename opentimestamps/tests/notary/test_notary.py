# Copyright (C) 2012 Peter Todd <pete@petertodd.org>
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution and at http://opentimestamps.org
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import unittest
import tempfile
import os
import shutil

from ...notary import *
from ...notary.test import *
from ... import client

class TestTestNotary(unittest.TestCase):
    def test_identity_canonicalization(self):
        notary = TestNotary(identity='notpass')
        self.assertEqual(notary.identity,'notpass')

        notary.canonicalize_identity()
        self.assertEqual(notary.identity,'fail-notpass')

    def test_signatures(self):
        pass_notary = TestNotary(identity='pass')
        fail_notary = TestNotary(identity='notpass')

        digest = b'hello world'

        (pass_sig_ops,pass_sig) = pass_notary.sign(digest,1)
        (fail_sig_ops,fail_sig) = fail_notary.sign(digest,1)
        self.assertEqual(fail_notary.identity,'fail-notpass')

        self.assertEqual(len(pass_sig_ops), 1)
        self.assertIn(digest, pass_sig_ops[0])
        self.assertEqual(len(fail_sig_ops), 1)
        self.assertIn(digest, fail_sig_ops[0])

        pass_sig.verify(pass_sig_ops[0])
        with self.assertRaises(SignatureVerificationError):
            pass_sig.verify(pass_sig_ops[0] + b'junk')

        with self.assertRaises(SignatureVerificationError):
            fail_sig.verify(fail_sig_ops[0])
        with self.assertRaises(SignatureVerificationError):
            fail_sig.verify(fail_sig_ops[0] + b'junk')
