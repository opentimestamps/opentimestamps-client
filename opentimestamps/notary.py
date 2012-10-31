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

from . import serialization

notary_methods_by_name = {}


def register_notary_method(cls):
    cls.method_name = str(cls.method_name)
    notary_methods_by_name[cls.method_name] = cls
    cls.validate_method_name()

    try:
        cls.digested_attributes = cls.__dict__['serialized_attributes']
    except KeyError:
        pass
    return serialization.digestible_serialized_object_subclass('ots.notary')(cls)


def register_signature_class(cls):
    return serialization.digestible_serialized_object_subclass('ots.notary')(cls)


class SignatureError(Exception):
    pass


class SignatureVerificationError(SignatureError):
    pass


@register_notary_method
class Notary(serialization.DigestibleSerializedObject):
    """Notary base class"""

    method_name = '_null'

    method_name_regex = '^(_*[a-z][a-z0-9\-\.\+]+|\*)$'
    method_name_re = re.compile(method_name_regex)

    compatible_versions = ()

    canonical_identity_regex = '^[A-Za-z0-9\@\:\-\_]*$'
    canonical_identity_re = re.compile(canonical_identity_regex) 

    identity_regex = '^([A-Za-z0-9\@\:\-\_ ]*|\*)$'
    identity_re = re.compile(identity_regex)

    serialized_attributes = ('method','identity','version')

    @classmethod
    def validate_method_name(cls,method_name=None):
        if not method_name:
            method_name = cls.method_name
        if not isinstance(method_name,str):
            raise TypeError('method_name must be unicode string; got type %r' % method_name.__class__)

        if not re.match(cls.method_name_re,method_name):
            raise ValueError("Invalid notary method name '%s' for method %s" % 
                    (method_name,cls.method_name))


    @classmethod
    def validate_method_version(cls,version):
        if not isinstance(version,int):
            raise TypeError('Notary method version must be an integer; got type %r' % version.__class__)

        # Delibrately limiting versions to something small. If you need some
        # crazy bitfield for a dozen options, do something else.
        if not 0 < version < 64:
            raise ValueError('Notary method version must satisfy: 0 < version < 64; got %d',version)

        if cls.compatible_versions and version is not None:
            if version not in cls.compatible_versions:
                raise ValueError("Version %d not supported by notary %s; "
                        "supported versions: %s" % 
                        (version,cls.method_name,
                         ', '.join([str(i) for i in cls.compatible_versions])))

    @classmethod
    def validate_canonical_identity(cls,canonical_identity):
        if not isinstance(canonical_identity,str):
            raise TypeError('Canonical identity must be unicode string; got type %r' % canonical_identity.__class__)

        if not re.match(cls.canonical_identity_re,canonical_identity):
            raise ValueError("Invalid canonical notary identity '%s' for method %s" % (canonical_identity,cls.method_name))

    @classmethod
    def validate_method_identity(cls,identity):
        if not isinstance(identity,str):
            raise TypeError('identity must be unicode string; got type %r' % identity.__class__)

        if not re.match(cls.identity_re,identity):
            raise ValueError("Invalid notary identity '%s' for method %s" % (identity,cls.method_name))


    def __init__(self,method='_null',version=1,identity='',**kwargs):
        self.__dict__.update(kwargs)

        self.method = str(method)
        self.validate_method_name(self.method)

        # FIXME: what do we do when a newer version is on the network? we
        # probably should do the full version check not here, but at notary
        # verification time or something. Also add a NotaryVersionException or
        # some-such.
        self.version = version
        self.validate_method_version(self.version)

        self.identity = str(identity)
        self.validate_method_identity(self.identity)

        # Locking now lets serialization/deserialization work, yet still allows
        # you to create a notary with a non-canonical name and have the
        # instance do the canonicalization.
        try:
            self.validate_canonical_identity(self.identity)
        except ValueError:
            pass
        else:
            self.lock()

    def canonicalize_identity(self):
        self.validate_canonical_identity(self.identity)

    def canonicalized(self):
        try:
            self.validate_canonical_identity(self.identity)
        except ValueError:
            return False
        return True


    def sign(self,digest,timestamp):
        """Sign a digest and timestamp with this notary

        The notary identity will be canonicalized first.
        """
        self.canonicalize_identity()

    def __str__(self):
        return '{}:{}'.format(self.method,self.identity)


@register_signature_class
class Signature(serialization.SerializedObject):
    """The signature a notary produces"""

    serialized_attributes = ('timestamp','notary')

    @property
    def trusted_crypto(self):
        """The set of all cryptographic algorithms that are trusted by this signature

        By trusted, we mean algorithms that if they are *broken* the signature
        cannot be trusted to be valid.
        """
        return frozenset()

    expected_notary_class = Notary
    def __init__(self,notary=Notary(),timestamp=0,**kwargs):
        if not (isinstance(timestamp,int) or isinstance(timestamp,int)):
            raise TypeError("Timestamp must be an integer")
        elif timestamp < 0:
            raise ValueError("Timestamp must be a positive integer")

        # Note that creating a timestamp in the past is not an error to allow
        # the import of timestamps from other timestamping systems.
        self.timestamp = int(timestamp)

        if not isinstance(notary,self.expected_notary_class):
            raise SignatureError("Notary must be of class %r for %r type signatures; got %r" %\
                    (self.expected_notary_class,self.__class__,notary.__class__))
        self.notary = notary

        # FIXME: need to validate the notary version somewhere?

        self.__dict__.update(kwargs)

    def __str__(self):
        return "Signature(timestamp={},notary='{}')".format(self.timestamp,self.notary)

    def verify(self,digest):
        """Verify a digest"""
        raise SignatureVerificationError



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
