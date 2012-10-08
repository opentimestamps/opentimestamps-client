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

import re

import pyme
import pyme.core
import pyme.pygpgme

from binascii import hexlify

from . import serialization

notary_methods_by_name = {}


def register_notary_method(cls):
    cls.method_name = unicode(cls.method_name)
    notary_methods_by_name[cls.method_name] = cls
    cls.validate_method_name()

    serialization.make_simple_object_serializer(cls,'ots.notary')

    return cls


def register_signature_class(cls):
    serialization.make_simple_object_serializer(cls,'ots.notary')
    return cls


class SignatureError(StandardError):
    pass


class SignatureVerificationError(SignatureError):
    pass


@register_notary_method
class Notary(serialization.ObjectWithDictEquality):
    """Notary base class"""

    method_name = u'_null'

    method_name_regex = u'^(_*[a-z][a-z0-9\-\.\+]+|\*)$'
    method_name_re = re.compile(method_name_regex)

    compatible_versions = ()

    canonical_identity_regex = u'^[A-Za-z0-9\@\:\-\_]*$'
    canonical_identity_re = re.compile(canonical_identity_regex) 

    identity_regex = u'^([A-Za-z0-9\@\:\-\_ ]*|\*)$'
    identity_re = re.compile(identity_regex)

    @classmethod
    def validate_method_name(cls,method_name=None):
        if not method_name:
            method_name = cls.method_name
        if not isinstance(method_name,unicode):
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
        if not isinstance(canonical_identity,unicode):
            raise TypeError('Canonical identity must be unicode string; got type %r' % canonical_identity.__class__)

        if not re.match(cls.canonical_identity_re,canonical_identity):
            raise ValueError("Invalid canonical notary identity '%s' for method %s" % (canonical_identity,cls.method_name))

    @classmethod
    def validate_method_identity(cls,identity):
        if not isinstance(identity,unicode):
            raise TypeError('identity must be unicode string; got type %r' % identity.__class__)

        if not re.match(cls.identity_re,identity):
            raise ValueError("Invalid notary identity '%s' for method %s" % (identity,cls.method_name))


    def __init__(self,method='_null',version=1,identity='',**kwargs):
        self.__dict__.update(kwargs)

        self.method = unicode(method)
        self.validate_method_name(self.method)

        # FIXME: what do we do when a newer version is on the network? we
        # probably should do the full version check not here, but at notary
        # verification time or something. Also add a NotaryVersionException or
        # some-such.
        self.version = version
        self.validate_method_version(self.version)

        self.identity = unicode(identity)
        self.validate_method_identity(self.identity)


    def canonicalize_identity(self):
        self.validate_canonical_identity(self.identity)


    def sign(self,digest,timestamp):
        """Sign a digest and timestamp with this notary

        The notary identity will be canonicalized first.
        """
        self.canonicalize_identity()



@register_signature_class
class Signature(serialization.ObjectWithDictEquality):
    """The signature a notary produces"""

    expected_notary_class = Notary
    def __init__(self,notary=Notary(),timestamp=0,**kwargs):
        if not (isinstance(timestamp,int) or isinstance(timestamp,long)):
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
    canonical_identity_regex = u'^(pass|fail)[a-z0-9\-\_]*$'
    canonical_identity_re = re.compile(canonical_identity_regex) 

    identity_regex = u'^([a-z0-9\-\_]*|\*)$'
    identity_re = re.compile(identity_regex)

    def __init__(self,method='test',**kwargs):
        super(TestNotary,self).__init__(method=method,**kwargs)

    def canonicalize_identity(self):
        # FIXME: before this, we should be checking if the identity is a search
        # string. Or scrap the search idea.

        # Example of identity re-writing while canonicalizing.
        if not (self.identity.startswith('pass') or self.identity.startswith('fail')):
            # Identity is a failure by not having 'pass' at the front
            if len(self.identity) > 0:
                self.identity = u'-' + self.identity
            self.identity = u'fail' + self.identity

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
        elif self.notary.identity.startswith(u'fail'):
            raise SignatureVerificationError


def _setup_pyme_context(context):
    gpg_ctx = pyme.core.Context()

    try:
        gpg_ctx.set_engine_info(gpg_ctx.get_protocol(),None,context.gpg_home_dir)
    except AttributeError:
        pass

    return gpg_ctx

@register_notary_method
class PGPNotary(Notary):
    """PGP notary"""

    method_name = 'pgp'

    method_name_regex = '^%s$' % method_name
    method_name_re = re.compile(method_name_regex)

    compatible_versions = (1,)

    canonical_identity_regex = '^[a-f0-9]+$' # hex digits
    canonical_identity_re = re.compile(canonical_identity_regex) 

    def __init__(self,method='pgp',version=1,**kwargs):
        super(PGPNotary,self).__init__(method=method,version=version,**kwargs)


    def canonicalize_identity(self):
        self.identity = self.identity.lower().replace(' ','')
        # FIXME: basically we should ask GPG to resolve the identity string
        super(PGPNotary,self).canonicalize_identity()


    def make_verification_message(self,digest,otstime):
        str_id = self.identity.encode('utf8')
        str_digest = hexlify(digest)
        str_time = '%d' % otstime
        return b"The owner of the PGP key with fingerprint "+str_id+" certifies that the digest "+str_digest+" existed on, or before, "+str_time+" microseconds after Jan 1st 1970 00:00 UTC. (the Unix epoch)"""


    def sign(self,digest,timestamp,context=None):
        super(PGPNotary,self).sign(digest,timestamp)

        msg = self.make_verification_message(digest,timestamp)

        gpg_ctx = _setup_pyme_context(context)

        signing_key = gpg_ctx.get_key(bytes(self.identity),0)
        gpg_ctx.signers_add(signing_key)

        msg_buf = pyme.core.Data(msg)
        sig_buf = pyme.core.Data()

        gpg_ctx.op_sign(msg_buf,sig_buf,pyme.pygpgme.GPGME_SIG_MODE_DETACH)

        # FIXME: so SEEK_SET should be defined somewhere...
        sig_buf.seek(0,0)

        pgp_sig = sig_buf.read()

        return PGPSignature(msg=msg,notary=self,timestamp=timestamp,pgp_sig=pgp_sig)


class PGPSignatureVerificationError(SignatureVerificationError):
    def __init__(self,gpg_error):
        msg = str(gpg_error)
        super(PGPSignatureVerificationError,self).__init__(msg)
        self.gpg_error = gpg_error

@register_signature_class
class PGPSignature(Signature):
    expected_notary_class = PGPNotary
    def __init__(self,**kwargs):
        super(PGPSignature,self).__init__(**kwargs)

    def verify(self,digest,context=None):
        msg = self.notary.make_verification_message(digest,self.timestamp)

        gpg_ctx = _setup_pyme_context(context)

        msg_buf = pyme.core.Data(msg)
        sig_buf = pyme.core.Data(self.pgp_sig)
        gpg_ctx.op_verify(sig_buf,msg_buf,None)
        result = gpg_ctx.op_verify_result()

        index = 0
        for sign in result.signatures:
            try:
                pyme.errors.errorcheck(sign.status)
            except pyme.errors.GPGMEError as gpg_error:
                raise PGPSignatureVerificationError(gpg_error)
