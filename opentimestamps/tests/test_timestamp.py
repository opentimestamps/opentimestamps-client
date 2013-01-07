# Copyright (C) 2012-2013 Peter Todd <pete@petertodd.org>
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
import io
import json

from opentimestamps._internal import hexlify,unhexlify
from opentimestamps.dag import Hash
from opentimestamps.timestamp import Timestamp,TimestampVerificationError
from opentimestamps.notary.test import TestSignature

#from opentimestamps.test.notary.pgp import setup_pgp_test_environment

def make_op_round_trip_tester(self):
    def r(value,expected_representation=None,new_value=None):
        # serialize to primitives
        actual_representation = value.to_primitives()
        if expected_representation is not None:
            self.assertEqual(actual_representation,expected_representation)

        # take that representation and send it through a json parser
        post_json_representation = json.loads(json.dumps(actual_representation))

        # deserialize that and check if it's what we expect
        value2 = Op.from_primitives(post_json_representation)
        if new_value is not None:
            value = new_value
        self.assertEqual(value,value2)
    return r

class TestTimestamp(unittest.TestCase):
    def test_add_algorithms(self):
        # no input
        data_fd = io.BytesIO(b'')
        ts = Timestamp(data_fd=data_fd)
        ts.add_algorithms('sha256')

        self.assertEqual(ts.digests,
                {'sha256':\
b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U"})

        # less than a single block
        data_fd = io.BytesIO(b'foo')
        ts = Timestamp(data_fd=data_fd)
        ts.add_algorithms('sha256','sha256d')

        self.assertEqual(ts.digests,
                {'sha256':\
b',&\xb4kh\xff\xc6\x8f\xf9\x9bE<\x1d0A4\x13B-pd\x83\xbf\xa0\xf9\x8a^\x88bf\xe7\xae',
                 'sha256d':\
b'\xc7\xad\xe8\x8f\xc7\xa2\x14\x98\xa6\xa5\xe5\xc3\x85\xe1\xf6\x8b\xed\x82+r\xaac\xc4\xa9\xa4\x8a\x02\xc2Fn\xe2\x9e'})

        # multiple blocks worth of data
        data_fd = io.BytesIO(b'\x00'*32000)
        ts = Timestamp(data_fd=data_fd)
        ts.add_algorithms('sha256','sha256d')

        self.assertEqual(ts.digests,
                {'sha256':\
b"\x0c\x92\xbd\xdbN\x96\xf3\xea\x9e\xc9\xf0\xf6Jf\x82U\xa6\xc1U'\xac\t\xf6\xf1\x19\xca\xfd\xe6\x0c|J9",
                 'sha256d':\
b'\xbax\xcf\x8c\xdc\xe8Q\xf5\xce0\xa3\xdc\xf1\xf0\xfc\rp\xd6\x9c\x9f\xa7\xbe\x87\x15\x01\x0cM\xee\xa5\x97\x11\xbd'})

    def test_add_algorithms_finds_corruption(self):
        data_fd = io.BytesIO(b'')
        ts = Timestamp(data_fd=data_fd)
        ts.add_algorithms('sha256')

        ts.data_fd = io.BytesIO(b'foo')
        with self.assertRaises(TimestampVerificationError):
            ts.add_algorithms()

        ts.data_fd = io.BytesIO(b'foo')
        with self.assertRaises(TimestampVerificationError):
            ts.add_algorithms('sha512')

    def test_verify_consistency(self):
        data_fd = io.BytesIO(b'')
        ts = Timestamp(data_fd=data_fd)

        # Should work, no sigs yet
        ts.verify_consistency()
        ts.add_algorithms('sha256')
        ts.verify_consistency()

        data_digest = bytes(Hash(b'',algorithm='sha256'))

        test_sig = TestSignature(identity='pass', digest=b'invalid')
        ts.signatures.add(test_sig)

        with self.assertRaises(TimestampVerificationError):
            ts.verify_consistency()
        ts.signatures.pop()

        # Add signature signing one of the data digests directly
        test_sig = TestSignature(identity='pass', digest=data_digest)
        ts.signatures.add(test_sig)
        ts.verify_consistency()

        # Add some ops this time
        nonce_op = Hash(data_digest,b'\xff' * 32,parents=(data_digest,))
        ts.dag.add(nonce_op)
        ts.signatures.add(TestSignature(identity='pass', digest=nonce_op))
        ts.verify_consistency()

        hash_op = Hash(bytes(nonce_op),b'green eggs and ham')
        ts.dag.add(hash_op)
        ts.signatures.add(TestSignature(identity='pass', digest=hash_op))
        ts.verify_consistency()

        # Break the chain
        ts.dag.remove(nonce_op)
        with self.assertRaises(TimestampVerificationError):
            ts.verify_consistency()

    def test_primitives(self):
        data_fd = io.BytesIO(b'')
        ts = Timestamp(data_fd=data_fd)
        data_digest = bytes(Hash(b'',algorithm='sha256'))

        self.assertEqual(ts.to_primitives(),
                dict(signatures = [], digests = {}, ops = []))

        ts.add_algorithms('sha256')
        self.assertEqual(ts.to_primitives(),
                dict(signatures = [],
                     digests = dict(sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
                     ops = []))

        ts.signatures.add(TestSignature(identity='pass', digest=data_digest))
        self.assertEqual(ts.to_primitives(),
                dict(signatures = [{'test':{'digest':0, 'identity':'pass'}}],
                     digests = dict(sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
                     ops = []))


        ts.dag.add(Hash(ts.digests['sha256'], algorithm='sha256'))
        self.assertEqual(ts.to_primitives(),
                dict(signatures = [{'test':{'digest':0, 'identity':'pass'}}],
                     digests = dict(sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
                     ops = [{'Hash': {'algorithm': 'sha256',
                                      'input': [1],
                                      'metadata': {},
                                      'parents': [(0, 32)]}}]))

        self.maxDiff = None
        ts.dag.add(Hash(ts.digests['sha256'], ts.digests['sha256'], b'foobar', algorithm='sha256'))
        self.assertEqual(ts.to_primitives(),
                dict(signatures = [{'test':{'digest':0, 'identity':'pass'}}],
                     digests = dict(sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
                     ops = [{'Hash': {'algorithm': 'sha256',
                                      'input': [1],
                                      'metadata': {},
                                      'parents': [(0, 32)]}},
                            {'Hash': {'algorithm': 'sha256',
                                      'input': [2, 2, '666f6f626172'],
                                      'metadata': {},
                                      'parents': [(0, 32), (64, 6)]}}]))

