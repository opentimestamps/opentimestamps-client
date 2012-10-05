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

import jsonrpclib

from .serialization import json_serialize,json_deserialize

class OtsServer(object):
    """JsonRPC marshaller proxy

    Quick-n-dirty
    """

    # FIXME: We should be doing things like ensuring the server is the right
    # version here.

    def __init__(self,url):
        self.__server = jsonrpclib.Server(url)

    def __getattr__(self,name):
        fn = getattr(self.__server,name)

        def marshalled_fn(*args):
            json_args = [json_serialize(arg) for arg in args]
            json_response = fn(*json_args)
            return json_deserialize(json_response)

        return marshalled_fn
