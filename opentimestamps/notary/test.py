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

@register_notary_method
class TestNotary(Notary):
    """Test notary

    Either always validates, or never validates, depending on the identity
    given. 
    """

    method_name = 'test'

    method_name_regex = '^%s$' % method_name
    method_name_re = re.compile(method_name_regex)

    compatible_versions = (1,)

    # pass or fail, followed by disambiguation
    canonical_identity_regex = '^(pass|fail)[a-z0-9\-\_]*$'
    canonical_identity_re = re.compile(canonical_identity_regex) 

    identity_regex = '^([a-z0-9\-\_]*|\*)$'
    identity_re = re.compile(identity_regex)

    serialized_attributes = ('_trusted_crypto',)

    @property
    def trusted_crypto(self):
        return self._trusted_crypto

    def __init__(self,method='test',trusted_crypto=(),**kwargs):
        self._trusted_crypto = trusted_crypto
        super(TestNotary,self).__init__(method=method,**kwargs)

    def canonicalize_identity(self):
        # FIXME: before this, we should be checking if the identity is a search
        # string. Or scrap the search idea.

        # Example of identity re-writing while canonicalizing.
        if not (self.identity.startswith('pass') or self.identity.startswith('fail')):
            # Identity is a failure by not having 'pass' at the front
            if len(self.identity) > 0:
                self.identity = '-' + self.identity
            self.identity = 'fail' + self.identity

        super(TestNotary,self).canonicalize_identity()

    def sign(self,digest,timestamp):
        super(TestNotary,self).sign(digest,timestamp)
        return TestSignature(expected_digest=digest,timestamp=timestamp,notary=self)

@register_signature_class
class TestSignature(Signature):
    expected_notary_class = TestNotary
    def __init__(self,**kwargs):
        super(TestSignature,self).__init__(**kwargs)

    def verify(self,digest):
        if digest != self.expected_digest:
            raise SignatureVerificationError
        elif self.notary.identity.startswith('fail'):
            raise SignatureVerificationError
