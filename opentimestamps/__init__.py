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

# Standard python version
__version__ = u'0.0'

# Perhaps a bit overkill, but given that this is cryptographic software, where
# any bugs will render the resulting timestamps totally invalid, it's probably
# worth giving lots of way to track down exactly what happened.
git_revision = u'$Id$'
try:
    git_revision = git_revision.split(' ')[1]
except IndexError:
    git_revision = u'(unknown git revision)'

# Implementation identitifier. Hopefully this will give enough info to track
# down any problems.
implementation_identifier = u'OpenTimestamps Client v%s - %s' % \
        (__version__,git_revision)
