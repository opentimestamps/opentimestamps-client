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

from ..serialization import *
from ..notary import *
from .. import client
from .test_serialization import make_json_round_trip_tester, make_binary_round_trip_tester

class TestTestNotary(unittest.TestCase):
    def test_serialization(self):
        rj = make_json_round_trip_tester(self)
        rb = make_binary_round_trip_tester(self)

        pass_notary = TestNotary(identity='pass')

        rj(pass_notary,
                {'ots.notary.TestNotary': 
                    {'_trusted_crypto': [],
                     'identity': 'pass',
                     'method': 'test',
                     'version': 1}})

        rb(pass_notary,b'\t\x15ots.notary.TestNotary\x0f_trusted_crypto\x07\x08\x08identity\x04\x04pass\x06method\x04\x04test\x07version\x02\x02\x00')

    def test_identity_canonicalization(self):
        notary = TestNotary(identity='notpass')
        self.assertEqual(notary.identity,'notpass')

        notary.canonicalize_identity()
        self.assertEqual(notary.identity,'fail-notpass')

    def test_signatures(self):
        pass_notary = TestNotary(identity='pass')
        fail_notary = TestNotary(identity='notpass')

        digest = b'hello world'

        pass_sig = pass_notary.sign(digest,1)
        fail_sig = fail_notary.sign(digest,1)
        self.assertEqual(fail_notary.identity,'fail-notpass')

        pass_sig.verify(digest)
        with self.assertRaises(SignatureVerificationError):
            pass_sig.verify(digest + b'junk')

        with self.assertRaises(SignatureVerificationError):
            fail_sig.verify(digest)
        with self.assertRaises(SignatureVerificationError):
            fail_sig.verify(digest + b'junk')


class TestPGPNotary(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix='tmpPGPNotary')
        self.gpg_dir = self.temp_dir + '/gnupg'

        testing_key_dir = os.path.dirname(__file__) + '/test_keyring'

        shutil.copytree(os.path.dirname(__file__) + '/test_keyring',
                self.gpg_dir)

        self.context = client.Context()
        self.context.gpg_home_dir = self.gpg_dir


    def tearDown(self):
        shutil.rmtree(self.temp_dir)


    def test_verify(self):
        notary = PGPNotary(identity='7640 5A19 F705 A646 AFA7  38B6 DE69 50AE F204 6073')

        signature = notary.sign(b'foo',1,self.context)
        signature.verify(b'foo',self.context)

        with self.assertRaises(PGPSignatureVerificationError):
            signature.verify(b'food',self.context)

        signature.timestamp += 1
        with self.assertRaises(PGPSignatureVerificationError):
            signature.verify(b'foo',self.context)
