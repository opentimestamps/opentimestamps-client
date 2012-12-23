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

import io
import re

import opentimestamps._internal

notary_methods_by_name = {}


def register_notary_method(cls):
    return cls

signature_classes_by_method = {}
def register_signature_class(cls):
    signature_classes_by_method[cls.method] = cls
    return cls


class SignatureError(Exception):
    pass

class SignatureVerificationError(SignatureError):
    pass


class Notary:
    """Notary base class"""

    method_name = '_null'

    method_name_regex = '^(_*[a-z][a-z0-9\-\.\+]+|\*)$'
    method_name_re = re.compile(method_name_regex)

    compatible_versions = ()

    canonical_identity_regex = '^[A-Za-z0-9\@\:\-\_]*$'
    canonical_identity_re = re.compile(canonical_identity_regex)

    identity_regex = '^([A-Za-z0-9\@\:\-\_ ]*|\*)$'
    identity_re = re.compile(identity_regex)

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


    def __init__(self,method='_null',identity='',context=None,**kwargs):
        self.context = context

        self.method = str(method)
        self.validate_method_name(self.method)

        self.identity = str(identity)
        self.validate_method_identity(self.identity)

    def canonicalize_identity(self):
        self.validate_canonical_identity(self.identity)

    def canonicalized(self):
        try:
            self.validate_canonical_identity(self.identity)
        except ValueError:
            return False
        return True


    def __str__(self):
        return '{}:{}'.format(self.method,self.identity)


class Signature:
    """The signature a notary produces"""

    @property
    def trusted_crypto(self):
        """The set of all cryptographic algorithms that are trusted by this signature

        By trusted, we mean algorithms that if they are *broken* the signature
        cannot be trusted to be valid.
        """
        return frozenset()

    method = None

    @property
    def identity(self):
        return self._identity

    @property
    def digest(self):
        """The digest that is being signed by this Signature"""
        return self._digest

    @property
    def timestamp(self):
        raise NotImplementedError

    def __init__(self,method=None,identity=None,digest=None):
        assert method == self.method

        self._identity = identity
        assert isinstance(identity,str)

        self._digest = digest
        assert isinstance(digest,bytes)

    def __eq__(self, other):
        if not isinstance(other, Signature):
            return NotImplemented
        else:
            return self.method == other.method and self.identity == other.identity and self.digest == other.digest

    def __hash__(self):
        return hash((self.method, self.identity, self.digest))

    def verify(self,context=None):
        """Verify that the signature is correct

        Returns True on success, False on failure.
        """
        raise NotImplementedError

    def to_primitives(self):
        d = dict(identity=self.identity,
                 digest=opentimestamps._internal.hexlify(self.digest))
        return {self.method:d}

    @classmethod
    def from_primitives(cls, primitives):
        assert len(primitives.keys()) == 1
        method = tuple(primitives.keys())[0]
        primitives = primitives[method]
        identity = primitives['identity']
        digest = opentimestamps._internal.unhexlify(primitives['digest'])

        return signature_classes_by_method[method](method=method, identity=identity, digest=digest)

import opentimestamps.notary.test
import opentimestamps.notary.pgp
import opentimestamps.notary.bitcoin
