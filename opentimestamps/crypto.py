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

import binascii
import hashlib
import os
import struct

def random_bytes(n):
    return os.urandom(n)

hash_functions_by_name = {}

def register_hash_algorithm(cls):
    instance = cls()
    hash_functions_by_name[cls.name] = instance
    return instance

class HashAlgorithm:
    """A hash algorithm

    Provides one-pass and incremental hashing, as well as metadata.
    """
    name = None
    """Human readable name"""

    digest_size = None
    """Digest size in bytes"""

    doubled = False
    """True if this is a doubled hash"""

    _hashlib_func = None
    def incremental(self, data):
        """Hash data incrementally."""
        class incremental_hasher:
            def __init__(self2):
                self2._hasher = self._hashlib_func()
            def update(self2,data):
                self2._hasher.update(data)
            def digest(self2):
                digest = self2._hasher.digest()
                if self.doubled:
                    digest = self._hashlib_func(digest).digest()
                return digest
        h = incremental_hasher()
        h.name = self.name
        h.update(data)
        return h

    def __call__(self,data):
        """Hash data and return the digest"""
        digest = self.incremental(data).digest()
        return digest


@register_hash_algorithm
class crc32(HashAlgorithm):
    """CRC32 stored as big-endian

    Included to be able to behavior of hash collisions; DO NOT use where a
    cryptographically secure hash function is required!
    """
    name = 'crc32'
    digest_size = 4
    doubled = False # why bother...

    def incremental(self, data):
        class crc32_hasher:
            def __init__(self):
                self.crc = 0
            def update(self, data):
                self.crc = binascii.crc32(data, self.crc)
            def digest(self):
                return struct.pack('>L', self.crc)

        hasher = crc32_hasher()
        hasher.update(data)
        return hasher

@register_hash_algorithm
class sha1(HashAlgorithm):
    name = 'sha1'
    digest_size = 20
    doubled = False
    _hashlib_func = hashlib.sha1

@register_hash_algorithm
class sha256(HashAlgorithm):
    name = 'sha256'
    digest_size = 32
    doubled = False
    _hashlib_func = hashlib.sha256

@register_hash_algorithm
class sha512(HashAlgorithm):
    name = 'sha512'
    digest_size = 64
    doubled = False
    _hashlib_func = hashlib.sha512

@register_hash_algorithm
class sha256d(HashAlgorithm):
    name = 'sha256d'
    digest_size = 32
    doubled = True
    _hashlib_func = hashlib.sha256

@register_hash_algorithm
class sha512d(HashAlgorithm):
    name = 'sha512d'
    digest_size = 64
    doubled = True
    _hashlib_func = hashlib.sha512
