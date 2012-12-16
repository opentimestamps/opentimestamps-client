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
import struct
import time

from binascii import hexlify

from opentimestamps.dag import Digest
from opentimestamps.notary import *

def _setup_gpg(context):
    return gnupg.GPG(gnupghome=getattr(context,'gpg_home_dir',None))

@register_notary_method
class PGPNotary(Notary):
    """PGP notary"""

    method_name = 'pgp'

    method_name_regex = '^%s$' % method_name
    method_name_re = re.compile(method_name_regex)

    canonical_identity_regex = '^[a-f0-9]{40}$' # a fingerprint and nothing else
    canonical_identity_re = re.compile(canonical_identity_regex)

    def __init__(self,method='pgp',**kwargs):
        super().__init__(method=method,**kwargs)


    def canonicalize_identity(self):
        self.identity = self.identity.lower().replace(' ','')
        # FIXME: basically we should ask GPG to resolve the identity string
        super().canonicalize_identity()


    def sign(self, digest, timestamp=None, context=None):
        if timestamp is None:
            timestamp = time.time()
        timestamp = timestamp * 1000000

        gpg = _setup_gpg(context)
        self.canonicalize_identity()

        sig = gpg.sign(digest, detach=True, clearsign=False, binary=True, keyid=self.identity)

        if sig.data:
            digest_op = Digest(struct.pack('>QQ', timestamp, len(sig.data)), sig.data, digest, parents=(digest,))
            return ((digest_op,),PGPSignature(digest=digest_op, identity=self.identity))
        else:
            raise SignatureError('PGP signing failed: {}'.format(sig.stderr))


class PGPSignatureVerificationError(SignatureVerificationError):
    def __init__(self,gpg_error):
        msg = str(gpg_error)
        super().__init__(msg)
        self.gpg_error = gpg_error

@register_signature_class
class PGPSignature(Signature):
    """PGP Signature"""

    method = 'pgp'

    expected_notary_class = PGPNotary
    def __init__(self, method='pgp', **kwargs):
        super().__init__(method=method, **kwargs)

    @property
    def trusted_crypto(self):
        return frozenset() # FIXME: implement this!

    @property
    def timestamp(self):
        return struct.unpack('>Q', self.digest[0:8])[0] / 1000000

    def verify(self, context=None):
        # FIXME: do we need to check that the identities match?

        import tempfile

        gpg = _setup_gpg(context)

        # Yuck, since this is a detached sig, we have to actually put the
        # message into a file for python3-gnupg to verify against.
        with tempfile.NamedTemporaryFile(mode='wb+') as msg_file:
            sig_len = struct.unpack('>QQ', self.digest[0:16])[1]

            sig = self.digest[16:16+sig_len]
            signed_digest = self.digest[16+sig_len:]

            msg_file.write(signed_digest)
            msg_file.flush()

            verified = gpg.verify_file(io.BytesIO(sig), msg_file.name)

            if not verified.valid:
                raise PGPSignatureVerificationError(verified)
