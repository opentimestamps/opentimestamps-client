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

import StringIO
import binascii
import json
import struct
import uuid

import bz2
import zlib

from .serialization import *
from .dag import *

from . import implementation_identifier

# TODO: TimestampFile should really act as a context manager, IE:
#
# with TimeStampfile(in_filename,out_filename) as stampfile:
#    <do stuff>
#
# With the out_filename overwriting in_filename safely and atomically.

class TimestampFile(object):
    magic_uuid = uuid.UUID('0062fc5c-0d26-11e2-97e4-6f3bd8706b74')
    magic_str = unicode(magic_uuid)

    # The UUID is meant to be completely unambiguous magic bytes for the file
    # command. The text string is meant to give people something to google when
    # they're trying to figure out what the heck an ots file is. With the
    # version bytes that gives us 32 bytes of header magic, which fits
    # perfectly in a canonical hexdump.
    magic_bytes = magic_uuid.bytes + 'OpenTimestamps'

    binary_header_format = '%dsBBB' % len(magic_bytes)

    major_version = 0
    minor_version = 0

    dag = None

    COMPRESSOR_NONE   = 0
    COMPRESSOR_ZLIB   = 1
    COMPRESSOR_BZIP2  = 2

    compressor = COMPRESSOR_ZLIB

    def __init__(self,
            in_fd=None,out_fd=None,
            algorithms=('sha256',),
            digests=None,
            mode='binary',
            compressor='zlib'):

        if compressor == 'zlib':
            self.compressor = self.COMPRESSOR_ZLIB
        elif compressor == 'bzip2':
            self.compressor = self.COMPRESSOR_BZIP2
        elif compressor == 'none':
            self.compressor = self.COMPRESSOR_NONE
        else:
            assert False

        self.mode = mode
        self.algorithms = [unicode(a) for a in algorithms]
        self.digests = digests

        self.in_fd = in_fd
        self.out_fd = out_fd


    def read(self):
        if self.mode is 'binary':
            self.read_binary()
        elif self.mode is 'armored':
            self.read_armored()
        else:
            raise ValueError("Unknown timestamp file type '%s'" % self.mode)

    def read_armored(self):
        raise NotImplementedError

    def read_binary(self):
        self.header = \
                struct.unpack(
                    self.binary_header_format,
                    self.in_fd.read(struct.calcsize(self.binary_header_format)))

        (magic,major,minor,compressor) = self.header
        assert magic == self.magic_bytes
        assert major == self.major_version
        assert minor == self.minor_version


        in_bytes = self.in_fd.read()
        in_crc32 = in_bytes[-4:]
        in_bytes = in_bytes[:-4]

        uncompressed_bytes = None
        if compressor == self.COMPRESSOR_ZLIB:
            uncompressed_bytes = zlib.decompress(in_bytes)
        elif compressor == self.COMPRESSOR_BZIP2:
            uncompressed_bytes = bz2.decompress(in_bytes)
        elif compressor == self.COMPRESSOR_NONE:
            uncompressed_bytes = in_bytes
        else:
            assert False

        assert struct.unpack('>L',in_crc32)[0] == binascii.crc32(uncompressed_bytes) & 0xffffffff

        deser_fd = StringIO.StringIO(uncompressed_bytes)

        self.options = binary_deserialize(deser_fd)
        self.digests = binary_deserialize(deser_fd)


    def write(self):
        if self.mode is 'binary':
            self.write_binary()
        elif self.mode is 'armored':
            self.write_armored()
        else:
            raise ValueError("Unknown timestamp file type '%s'" % self.mode)

    def write_armored(self):
        raise NotImplementedError

    def write_binary(self):
        header = struct.pack(self.binary_header_format,
                self.magic_bytes,self.major_version,self.minor_version,self.compressor)
        self.out_fd.write(header)

        out_bytes = []

        # FIXME: we should have a CRC32 for the input file
        options = {'algorithms':self.algorithms,
                   'implementation_identifier':implementation_identifier}

        out_bytes.append(binary_serialize(options))

        out_bytes.append(binary_serialize(tuple(self.digests)))

        out_bytes = ''.join(out_bytes)

        compressed_bytes = None
        if self.compressor == self.COMPRESSOR_ZLIB:
            compressed_bytes = zlib.compress(out_bytes,9)
        elif self.compressor == self.COMPRESSOR_BZIP2:
            compressed_bytes = bz2.compress(out_bytes,9)
        elif self.compressor == self.COMPRESSOR_NONE:
            compressed_bytes = out_bytes
        else:
            assert False

        self.out_fd.write(compressed_bytes)
        crc32_bytes = struct.pack('>L',binascii.crc32(out_bytes) & 0xffffffff)
        self.out_fd.write(struct.pack('>L',binascii.crc32(out_bytes) & 0xffffffff))
