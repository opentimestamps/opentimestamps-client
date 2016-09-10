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

"""Consensus-critical code

Basically, everything under opentimestamps.core has the property that changes
to it may break timestamp validation in non-backwards-compatible ways that are
difficult to recover from. We keep such code separate as a reminder to
ourselves to pay extra attention when making changes.
"""
