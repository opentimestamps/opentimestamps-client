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
import io
import json

from ..op import *

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

def make_binary_round_trip_tester(self):
    def r(value,expected_representation=None,new_value=None):
        # serialize to binary representation
        actual_representation = binary_serialize(value)

        if expected_representation is not None:
            self.assertEqual(actual_representation,expected_representation)

        # deserialize that and check if it's what we expect
        value2 = binary_deserialize(actual_representation)
        if new_value is not None:
            value = new_value
        self.assertEqual(value,value2)
    return r

class TestOp(unittest.TestCase):
    def test_equality(self):
        a1 = Digest(digest=b'a')
        a2 = Digest(digest=b'a')
        b = Digest(digest=b'b')

        self.assertNotEqual(a1,object())

        self.assertEqual(a1,a2)
        self.assertEqual(a1,b'a')
        self.assertEqual(b,b'b')
        self.assertNotEqual(a1,b)
        self.assertNotEqual(a2,b)

    def test___hash__(self):
        a1 = Digest(digest=b'a')
        a2 = Digest(digest=b'a')
        b = Digest(digest=b'b')

        s = (a1,b)

        self.assertIn(b,s)
        self.assertIn(a1,s)
        self.assertIn(a2,s)

        a2.foo = 'bar'
        self.assertIn(a2,s)

class TestDigestOp(unittest.TestCase):
    def test_json_serialization(self):
        r = make_op_round_trip_tester(self)

        d = Digest(digest=b'\xff\x00')
        r(d,{'Digest': {'input': '', 'digest': 'ff00', 'parents': []}})

class TestHashOp(unittest.TestCase):
    def test_hash_algorithm_support(self):
        def t(algo,expected,d=(b'',)):
            h = Hash(*d,algorithm=algo)
            self.assertEqual(h,expected)

        t('sha256d',b']\xf6\xe0\xe2v\x13Y\xd3\n\x82u\x05\x8e)\x9f\xcc\x03\x81SEE\xf5\\\xf4>A\x98?]L\x94V')
        t('sha512d',b'\x82m\xf0hE}\xf5\xdd\x19[Cz\xb7\xe7s\x9f\xf7]&r\x18?\x02\xbb\x8e\x10\x89\xfa\xbc\xf9{\xd9\xdc\x80\x11\x0c\xf4-\xbc|\xffA\xc7\x8e\xcbh\xd8\xbax\xab\xe6\xb5\x17\x8d\xea9\x84\xdf\x8cUT\x1b\xf9I')

        t('crc32',b'\x00\x00\x00\x00')
        t('crc32',b':,\xcd\x8d',d=(b"Testing an awful hash algorithm.",))

    def test_json_serialization(self):
        r = make_op_round_trip_tester(self)

        h1 = Hash(b'a',b'b')
        r(h1,{'Hash':
                {'input':'6162',
                 'parents': [(0,1), (1,1)],
                 'algorithm':'sha256d',
                 'digest':'a1ff8f1856b5e24e32e3882edd4a021f48f28a8b21854b77fdef25a97601aace'}})

#class TestVerifyOp(unittest.TestCase):
#    def test_json_serialization(self):
#        r = make_json_round_trip_tester(self)
#
#        a = Digest(digest=b'a')
#        b = Digest(digest=b'b')
#        h1 = Hash(inputs=(a,b))
#        v = Verify(inputs=(h1,),notary_method='foo')
#        r(v)
#
#    def test_binary_serialization(self):
#        r = make_binary_round_trip_tester(self)
#        a = Digest(digest=b'a')
#        b = Digest(digest=b'b')
#        h1 = Hash(inputs=(a,b))
#        v = Verify(inputs=(h1,),notary_method='foo')
#        r(v)
#
#    def test_verify_digest_equality(self):
#        # Basically create two Verify ops that should have the same digest.
#        a = Digest(digest=b'a')
#        b = Digest(digest=b'b')
#        h1 = Hash(inputs=(a,b))
#        v = Verify(inputs=(h1,))
#
#        v2 = v
#        a = Digest(digest=b'a')
#        b = Digest(digest=b'b')
#        h1 = Hash(inputs=(a,b))
#        v = Verify(inputs=(h1,))
#
#        self.assertEqual(v,v2)
#
#        # and a third one that shouldn't
#        a = Digest(digest=b'a')
#        b = Digest(digest=b'b')
#        h1 = Hash(inputs=(a,b))
#        v = Verify(inputs=(h1,),signature=notary.Signature(timestamp=42))
#
#        self.assertNotEqual(v,v2)
#
#        # FIXME: better testing of this would be good
