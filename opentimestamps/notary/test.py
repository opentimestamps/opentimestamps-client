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

import struct
import time

from opentimestamps.dag import Digest
from opentimestamps.notary import *

test_notary_struct = struct.Struct('>Q')

@register_notary_method
class TestNotary(Notary):
    """Test notary

    Either always validates, or never validates, depending on the identity
    given.
    """

    method_name = 'test'

    method_name_regex = '^%s$' % method_name
    method_name_re = re.compile(method_name_regex)

    # pass or fail, followed by disambiguation
    canonical_identity_regex = '^(pass|fail)[a-z0-9\-\_]*$'
    canonical_identity_re = re.compile(canonical_identity_regex)

    identity_regex = '^([a-z0-9\-\_]*|\*)$'
    identity_re = re.compile(identity_regex)

    @property
    def trusted_crypto(self):
        return self._trusted_crypto

    def __init__(self,method='test',trusted_crypto=(),**kwargs):
        self._trusted_crypto = trusted_crypto
        super().__init__(method=method,**kwargs)

    def canonicalize_identity(self):
        # FIXME: before this, we should be checking if the identity is a search
        # string. Or scrap the search idea.

        # Example of identity re-writing while canonicalizing.
        if not (self.identity.startswith('pass') or self.identity.startswith('fail')):
            # Identity is a failure by not having 'pass' at the front
            if len(self.identity) > 0:
                self.identity = '-' + self.identity
            self.identity = 'fail' + self.identity

        super().canonicalize_identity()

    def sign(self,digest,timestamp=None):
        if timestamp is None:
            timestamp = time.time()

        self.canonicalize_identity()

        digest = Digest(test_notary_struct.pack(timestamp * 1000000), digest, parents=(digest,))
        sig = TestSignature(digest=digest, method=self.method, identity=self.identity)
        return ((digest,),sig)


@register_signature_class
class TestSignature(Signature):
    def __init__(self, method='test', **kwargs):
        super().__init__(method=method, **kwargs)

    @property
    def method(self):
        return 'test'

    @property
    def timestamp(self):
        return test_notary_struct.unpack(self.digest)[0] / 1000000

    def verify(self,digest):
        if self.identity.startswith('fail') or self.digest != digest:
            raise SignatureVerificationError
