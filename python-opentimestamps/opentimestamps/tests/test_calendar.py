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

import unittest

from opentimestamps.calendar import *

class Test_UrlWhitelist(unittest.TestCase):
    def test_empty(self):
        """Empty whitelist"""
        wl = UrlWhitelist()

        self.assertNotIn('', wl)
        self.assertNotIn('http://example.com', wl)

    def test_exact_match(self):
        """Exact match"""

        wl = UrlWhitelist(("https://example.com",))
        self.assertIn("https://example.com", wl)
        self.assertNotIn("http://example.com", wl)
        self.assertNotIn("http://example.org", wl)

        # I'm happy for this to be strict
        self.assertIn("https://example.com", wl)

    def test_add_scheme(self):
        """URL scheme added automatically"""
        wl = UrlWhitelist(("example.com",))
        self.assertIn("https://example.com", wl)
        self.assertIn("http://example.com", wl)

    def test_glob_match(self):
        """Glob matching"""
        wl = UrlWhitelist(("*.example.com",))
        self.assertIn("https://foo.example.com", wl)
        self.assertIn("http://bar.example.com", wl)
        self.assertIn("http://foo.bar.example.com", wl)

        self.assertNotIn("http://barexample.com", wl)
