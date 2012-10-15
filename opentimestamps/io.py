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
import io
import json
import struct
import uuid

import bz2
import zlib

from opentimestamps.dag import Dag,Verify
from opentimestamps.serialization import *
from opentimestamps._internal import BinaryHeader

from opentimestamps import implementation_identifier

class TimestampFile(BinaryHeader):
    header_magic_uuid = uuid.UUID('0062fc5c-0d26-11e2-97e4-6f3bd8706b74')
    header_magic_text = b'OpenTimestamps'

    major_version = 0
    minor_version = 0

    header_struct_format = 'B'
    header_field_names = ('compression_type',)

    COMPRESSOR_NONE   = 0
    COMPRESSOR_ZLIB   = 1
    COMPRESSOR_BZIP2  = 2

    compression_types_by_name = {'none' :0,
                                 'zlib' :1,
                                 'bzip2':2}

    # assuming timestamp files themselves will be able to fit in memory here...
    #
    # TODO: also eval before version 1.0 if both bz2 and zlib are really
    # useful. zlib is better for small stuff already.
    compressors_by_number =   {0:lambda b: b,
                               1:lambda b: zlib.compress(b,9),
                               2:lambda b:  bz2.compress(b,9)}

    decompressors_by_number = {0:lambda b: b,
                               1:lambda b: zlib.decompress(b),
                               2:lambda b:  bz2.decompress(b)}

    dag = None

    class TimestampError(Exception):
        pass
    class CorruptTimestampError(TimestampError):
        pass
    class InconsistentDigestsError(CorruptTimestampError):
        pass


    def __init__(self,
                 in_fd=None,out_fd=None,
                 digests=None,
                 ops=(),
                 mode='binary',
                 compressor='zlib'):

        try:
            self.compression_type = self.compression_types_by_name[compressor]
        except KeyError:
            raise ValueError('Unknown compression type %r' % compressor)

        self.compressor = compressor
        self.mode = mode
        self.dag = Dag(ops)
        if digests is None:
            digests = {}
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
        self._read_header(self.in_fd)

        in_bytes = self.in_fd.read()
        in_crc32 = in_bytes[-4:]
        in_bytes = in_bytes[:-4]

        try:
            decompress = self.decompressors_by_number[self.compression_type]
        except KeyError:
            raise self.CorruptTimestampError('Unknown compression type number %d' % self.compression_type)

        uncompressed_bytes = decompress(in_bytes)

        assert struct.unpack('>L',in_crc32)[0] == binascii.crc32(uncompressed_bytes) & 0xffffffff

        deser_fd = io.BytesIO(uncompressed_bytes)

        self.options = binary_deserialize(deser_fd)
        self.dag = Dag(binary_deserialize(deser_fd))

        # Make sure the digests specified match the ones in the file
        old_digests = self.options['digests']
        for algo,digest in self.digests.items():
            if algo in old_digests:
                if digest != old_digests[algo]:
                    raise self.InconsistentDigestsError(\
"Digest {}:{} doesn't match the one in the timestamp, {}:{}".format(\
    algo,binascii.hexlify(digest),
    algo,binascii.hexlify(old_digests[algo])))

            else:
                # Otherwise update
                old_digests[algo] = digest

        self.digests = old_digests


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
        self._write_header(self.out_fd)

        # Prune digests that aren't reachable from the digests we're
        # timestamping.
        root_digests = set(self.digests.values())
        self.dag = Dag(self.dag.children(root_digests))

        out_bytes = []

        options = {'digests':self.digests,
                   'implementation_identifier':implementation_identifier}

        out_bytes.append(binary_serialize(options))
        out_bytes.append(binary_serialize(tuple(self.dag)))
        out_bytes = b''.join(out_bytes)

        compressed_bytes = self.compressors_by_number[self.compression_type](out_bytes)

        self.out_fd.write(compressed_bytes)
        crc32_bytes = struct.pack('>L',binascii.crc32(out_bytes) & 0xffffffff)
        self.out_fd.write(struct.pack('>L',binascii.crc32(out_bytes) & 0xffffffff))
