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

import gnupg
import io
import re

from binascii import hexlify

def _setup_gpg(context):
    return gnupg.GPG(gnupghome=getattr(context,'gpg_home_dir',None))

@register_notary_method
class PGPNotary(Notary):
    """PGP notary"""

    method_name = 'pgp'

    method_name_regex = '^%s$' % method_name
    method_name_re = re.compile(method_name_regex)

    compatible_versions = (1,)

    canonical_identity_regex = '^[a-f0-9]{40}$' # a fingerprint and nothing else
    canonical_identity_re = re.compile(canonical_identity_regex)

    def __init__(self,method='pgp',version=1,**kwargs):
        super(PGPNotary,self).__init__(method=method,version=version,**kwargs)


    def canonicalize_identity(self):
        self.identity = self.identity.lower().replace(' ','')
        # FIXME: basically we should ask GPG to resolve the identity string
        super(PGPNotary,self).canonicalize_identity()


    def make_verification_message(self,digest,otstime):
        str_id = self.identity.encode('utf8')
        str_digest = str(hexlify(digest),'utf8')
        str_time = '%d' % otstime
        return bytes(
""""The owner of the PGP key with fingerprint %s certifies that the digest %s existed on, or before, %s microseconds after Jan 1st 1970 00:00 UTC. (the Unix epoch)""" % (str_id,str_digest,str_time),'utf8')


    def sign(self,digest,timestamp,context=None):
        super(PGPNotary,self).sign(digest,timestamp)

        gpg = _setup_gpg(context)

        msg = self.make_verification_message(digest,timestamp)
        sig = gpg.sign(msg,detach=True,clearsign=False,binary=True,keyid=self.identity)

        if sig:
            return PGPSignature(notary=self,timestamp=timestamp,sig=sig.data)
        else:
            # FIXME: need to get better error messages for this; python-gnupg
            # doesn't seem to throw an exception.
            raise SignatureError('PGP signing failed')


class PGPSignatureVerificationError(SignatureVerificationError):
    def __init__(self,gpg_error):
        msg = str(gpg_error)
        super(PGPSignatureVerificationError,self).__init__(msg)
        self.gpg_error = gpg_error

@register_signature_class
class PGPSignature(Signature):
    """PGP Signature

    

    """

    serialized_attributes = ('sig',)

    expected_notary_class = PGPNotary
    def __init__(self,**kwargs):
        super(PGPSignature,self).__init__(**kwargs)

    @property
    def trusted_crypto(self):
        return frozenset() # FIXME: implement this!

    def verify(self,digest,context=None):
        import tempfile

        msg = self.notary.make_verification_message(digest,self.timestamp)

        gpg = _setup_gpg(context)

        # Yuck, since this is a detached sig, we have to actually put the
        # message into a file for python3-gnupg to verify against.
        with tempfile.NamedTemporaryFile(mode='wb+') as msg_file:
            msg_file.write(msg)
            msg_file.flush()

            verified = gpg.verify_file(io.BytesIO(self.sig),msg_file.name)

            if not verified.valid:
                raise PGPSignatureVerificationError(verified)
