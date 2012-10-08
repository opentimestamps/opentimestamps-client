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

from ..serialization import *
from ..notary import *
from .test_serialization import make_json_round_trip_tester, make_binary_round_trip_tester

class TestTestNotary(unittest.TestCase):
    def test_serialization(self):
        rj = make_json_round_trip_tester(self)
        rb = make_binary_round_trip_tester(self)

        pass_notary = TestNotary(identity='pass')

        rj(pass_notary,
                {u'ots.notary.TestNotary': 
                    {'identity': u'pass',
                     'method': u'test',
                     'version': 1}})

        rb(pass_notary,b'\t\x15ots.notary.TestNotary\x08identity\x04\x04pass\x06method\x04\x04test\x07version\x02\x02\x00')

    def test_identity_canonicalization(self):
        notary = TestNotary(identity='not pass')
        self.assertEquals(notary.identity,u'not pass')

        notary.canonicalize_identity()
        self.assertEquals(notary.identity,u'fail')

    def test_signatures(self):
        pass_notary = TestNotary(identity='pass')
        fail_notary = TestNotary(identity='not pass')

        digest = b'hello world'

        pass_sig = pass_notary.sign(digest,1)
        fail_sig = fail_notary.sign(digest,1)
        self.assertEquals(fail_notary.identity,u'fail')

        self.assertTrue(pass_sig.verify(digest))
        self.assertFalse(pass_sig.verify(digest + 'junk'))

        self.assertFalse(fail_sig.verify(digest))
        self.assertFalse(fail_sig.verify(digest + 'junk'))


class TestPGPNotary(unittest.TestCase):
    pass
