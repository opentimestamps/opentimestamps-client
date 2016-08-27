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
import urllib.request

from opentimestamps.core.timestamp import Timestamp
from opentimestamps.core.serialize import StreamDeserializationContext

class RemoteCalendar:
    """Remote calendar server interface"""
    def __init__(self, url):
        if isinstance(url, bytes):
            # FIXME: is this safe? secure?
            url = url.decode('utf8')
        self.url = url

    def submit(self, digest):
        """Submit a digest to the calendar

        Returns a Timestamp committing to that digest
        """
        req = urllib.request.Request(self.url + '/digest', data=digest)
        with urllib.request.urlopen(req) as resp:
            if resp.status != 200:
                raise Exception("Unknown response from calendar: %d" % resp.status)

            ctx = StreamDeserializationContext(resp)
            return Timestamp.deserialize(ctx, digest)

    def get_timestamp(self, commitment):
        """Get a timestamp for a given commitment

        Raises KeyError if the calendar doesn't have that commitment
        """
        req = urllib.request.Request(self.url + '/timestamp/' + binascii.hexlify(commitment).decode('utf8'))
        with urllib.request.urlopen(req) as resp:
            if resp.status == 404:
                raise KeyError("Commitment not found")

            elif resp.status == 200:
                ctx = StreamDeserializationContext(resp)
                return Timestamp.deserialize(ctx, commitment)

            else:
                raise Exception("Unknown response from calendar: %d" % resp.status)
