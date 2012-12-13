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
import struct

crc32 = lambda d: struct.pack('>L',binascii.crc32(d))

sha256 = lambda d: hashlib.sha256(d).digest()
sha512 = lambda d: hashlib.sha512(d).digest()

sha256d = lambda d: sha256(sha256(d))
sha512d = lambda d: sha512(sha512(d))

hash_functions_by_name = dict(
        crc32   = crc32,
        sha256  = sha256,
        sha512  = sha512,
        sha256d = sha256d,
        sha512d = sha512d
        )
