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
import fnmatch

from opentimestamps.core.timestamp import Timestamp
from opentimestamps.core.serialize import BytesDeserializationContext

class RemoteCalendar:
    """Remote calendar server interface"""

    def __init__(self, url, user_agent="python-opentimestamps"):
        if not isinstance(url, str):
            raise TypeError("URL must be a string")
        self.url = url

        self.request_headers = {"Accept": "application/vnd.opentimestamps.v1",
                                "User-Agent": user_agent}

    def submit(self, digest):
        """Submit a digest to the calendar

        Returns a Timestamp committing to that digest
        """
        req = urllib.request.Request(self.url + '/digest', data=digest, headers=self.request_headers)
        with urllib.request.urlopen(req) as resp:
            if resp.status != 200:
                raise Exception("Unknown response from calendar: %d" % resp.status)

            # FIXME: Not a particularly nice way of handling this, but it'll do
            # the job for now.
            resp_bytes = resp.read(10000)
            if len(resp_bytes) > 10000:
                raise Exception("Calendar response exceeded size limit")

            ctx = BytesDeserializationContext(resp_bytes)
            return Timestamp.deserialize(ctx, digest)

    def get_timestamp(self, commitment):
        """Get a timestamp for a given commitment

        Raises KeyError if the calendar doesn't have that commitment
        """
        req = urllib.request.Request(self.url + '/timestamp/' + binascii.hexlify(commitment).decode('utf8'),
                                     headers=self.request_headers)
        try:
            with urllib.request.urlopen(req) as resp:
                if resp.status == 200:

                    # FIXME: Not a particularly nice way of handling this, but it'll do
                    # the job for now.
                    resp_bytes = resp.read(10000)
                    if len(resp_bytes) > 10000:
                        raise Exception("Calendar response exceeded size limit")

                    ctx = BytesDeserializationContext(resp_bytes)
                    return Timestamp.deserialize(ctx, commitment)

                else:
                    raise Exception("Unknown response from calendar: %d" % resp.status)
        except urllib.error.HTTPError as exp:
            if exp.code == 404:
                raise KeyError("Commitment not found")
            else:
                raise exp

class UrlWhitelist(set):
    """Glob-matching whitelist for URL's"""

    def __init__(self, urls=()):
        for url in urls:
            self.add(url)

    def add(self, url):
        if not isinstance(url, str):
            raise TypeError("URL must be a string")

        if url.startswith('http://') or url.startswith('https://'):
            parsed_url = urllib.parse.urlparse(url)

            # FIXME: should have a more friendly error message
            assert not parsed_url.params and not parsed_url.query and not parsed_url.fragment

            set.add(self, parsed_url)

        else:
            self.add('http://' + url)
            self.add('https://' + url)

    def __contains__(self, url):
        parsed_url = urllib.parse.urlparse(url)

        # FIXME: probably should tell user why...
        if parsed_url.params or parsed_url.query or parsed_url.fragment:
            return False

        for pattern in self:
            if (parsed_url.scheme == pattern.scheme and
                    parsed_url.path == pattern.path and
                    fnmatch.fnmatch(parsed_url.netloc, pattern.netloc)):
                return True

        else:
            return False
