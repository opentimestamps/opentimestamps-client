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
from ...notary.pgp import *
from ... import client

class TestPGPNotary(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix='tmpPGPNotary')
        self.gpg_dir = self.temp_dir + '/gnupg'

        testing_key_dir = os.path.dirname(__file__) + '/test_keyring'

        shutil.copytree(os.path.dirname(__file__) + '/test_keyring',
                self.gpg_dir)

        # Fix permissions
        os.chmod(self.gpg_dir,0o700)
        os.chmod(self.gpg_dir + '/secring.gpg',0o600)

        self.context = client.Context()
        self.context.gpg_home_dir = self.gpg_dir


    def tearDown(self):
        shutil.rmtree(self.temp_dir)


    def test_verify(self):
        notary = PGPNotary(identity='7640 5A19 F705 A646 AFA7  38B6 DE69 50AE F204 6073')

        (ops, signature) = notary.sign(b'foo', timestamp=1, context=self.context)

        self.assertEqual(len(ops), 1)
        self.assertIn(b'foo', ops[0])

        self.assertEqual(signature.timestamp, 1)

        signature.verify(self.context)

        signature._digest += b'junk'
        with self.assertRaises(PGPSignatureVerificationError):
            signature.verify(self.context)
