# Copyright (C) 2016 The OpenTimestamps developers
#
# This file is part of python-opentimestamps.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-opentimestamps including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import binascii
import io

class DeserializationError(Exception):
    """Base class for all errors encountered during deserialization"""

class BadMagicError(DeserializationError):
    """A magic number is incorrect

    Raise this when a file format magic number is incorrect.
    """
    def __init__(self, expected_magic, actual_magic):
        super().__init__('Expected magic bytes 0x%s, but got 0x%s instead' % (binascii.hexlify(expected_magic).decode(),
                                                                              binascii.hexlify(actual_magic).decode()))

class TruncationError(DeserializationError):
    """Truncated data encountered while deserializing"""

class SerializerTypeError(TypeError):
    """Wrong type for specified serializer"""

class SerializerValueError(ValueError):
    """Inappropriate value to be serialized (of correct type)"""


class SerializationContext:
    """Context for serialization

    Allows multiple serialization targets to share the same codebase, for
    instance bytes, memoized serialization, hashing, etc.
    """

    def write_bool(self, value):
        """Write a bool"""
        raise NotImplementedError

    def write_varuint(self, value):
        """Write a variable-length unsigned integer"""
        raise NotImplementedError

    def write_bytes(self, value):
        """Write fixed-length bytes"""
        raise NotImplementedError

    def write_varbytes(self, value):
        """Write variable-length bytes"""
        raise NotImplementedError

class DeserializationContext:
    """Context for deserialization

    Allows multiple deserialization sources to share the same codebase, for
    instance bytes, memoized serialization, hashing, etc.
    """
    def read_bool(self):
        """Read a bool"""
        raise NotImplementedError

    def read_varuint(self, max_int):
        """Read a variable-length unsigned integer"""
        raise NotImplementedError

    def read_bytes(self, expected_length):
        """Read fixed-length bytes"""
        raise NotImplementedError

    def read_varbytes(self, value, max_length=None):
        """Read variable-length bytes

        No more than max_length bytes will be read.
        """
        raise NotImplementedError


class StreamSerializationContext(SerializationContext):
    def __init__(self, fd):
        """Serialize to a stream"""
        self.fd = fd

    def write_bool(self, value):
        if value is True:
            self.fd.write(b'\xff')

        elif value is False:
            self.fd.write(b'\x00')

        else:
            raise TypeError('Expected bool; got %r' % value.__class__)

    def write_varuint(self, value):
        # unsigned little-endian base128 format (LEB128)
        if value == 0:
            self.fd.write(b'\x00')

        else:
            while value != 0:
                b = value & 0b01111111
                if value > 0b01111111:
                    b |= 0b10000000
                self.fd.write(bytes([b]))
                if value <= 0b01111111:
                    break
                value >>= 7

    def write_bytes(self, value):
        self.fd.write(value)

    def write_varbytes(self, value):
        self.write_varuint(len(value))
        self.fd.write(value)

class StreamDeserializationContext(DeserializationContext):
    def __init__(self, fd):
        """Deserialize from a stream"""
        self.fd = fd

    def fd_read(self, l):
        r = self.fd.read(l)
        if len(r) != l:
            raise TruncationError('Tried to read %d bytes but got only %d bytes' % \
                                  (l, len(r)))
        return r

    def read_bool(self):
        # unsigned little-endian base128 format (LEB128)
        b = self.fd_read(1)[0]
        if b == 0xff:
            return True

        elif b == 0x00:
            return False

        else:
            raise DeserializationError('read_bool() expected 0xff or 0x00; got %d' % b)

    def read_varuint(self):
        value = 0
        shift = 0

        while True:
            b = self.fd_read(1)[0]
            value |= (b & 0b01111111) << shift
            if not (b & 0b10000000):
                break
            shift += 7

        return value

    def read_bytes(self, expected_length=None):
        if expected_length is None:
            expected_length = self.read_varuint(None)
        return self.fd_read(expected_length)

    def read_varbytes(self, max_len, min_len=0):
        l = self.read_varuint()
        if l > max_len:
            raise DeserializationError('varbytes max length exceeded; %d > %d' % (l, max_len))
        if l < min_len:
            raise DeserializationError('varbytes min length not met; %d < %d' % (l, min_len))
        return self.fd_read(l)

class BytesSerializationContext(StreamSerializationContext):
    def __init__(self):
        """Serialize to bytes"""
        super().__init__(io.BytesIO())

    def getbytes(self):
        """Return the bytes serialized to date"""
        return self.fd.getvalue()

class BytesDeserializationContext(StreamDeserializationContext):
    def __init__(self, buf):
        """Deserialize from bytes"""
        super().__init__(io.BytesIO(buf))

    # FIXME: need to check that there isn't extra crap at end of object
