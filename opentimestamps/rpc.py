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

import json
import logging
import urllib.error
import urllib.request
from urllib.parse import quote_plus,unquote_plus,urlencode

from .serialization import json_serialize,json_deserialize

class OtsServer:
    """Interface to an OpenTimestamps Server"""

    # FIXME: We should be doing things like ensuring the server is the right
    # version here.

    def __init__(self,url):
        self.url = url

    def __getattr__(self,name):

        fn = None
        if name.startswith('get_'):
            name = name[4:]

            def get_fn(*args,**kwargs):
                kwargs = {k: quote_plus(json.dumps(json_serialize(v))) for k,v in kwargs.items()}
                kwargs = urlencode(kwargs)
                if kwargs:
                    kwargs = '?' + kwargs

                args = [quote_plus(json.dumps(json_serialize(arg))) for arg in args]
                args = '/'.join(args)
                if args:
                    args = '/' + args

                try:
                    with urllib.request.urlopen(self.url + '/' + name + args + kwargs) as r:
                        return json_deserialize(json.loads(str(r.read(),'utf8')))
                except urllib.error.HTTPError as ex:
                    logging.error(str(ex.read(),'utf8'))
                    raise ex
            fn = get_fn
        elif name.startswith('post_'):
            name = name[5:]

            def post_fn(*args,**kwargs):
                kwargs = {k: json.dumps(json_serialize(v)) for k,v in kwargs.items()}
                kwargs = bytes(urlencode(kwargs),'utf8')

                args = [quote_plus(json.dumps(json_serialize(arg))) for arg in args]
                args = '/'.join(args)
                if args:
                    args = '/' + args

                try:
                    with urllib.request.urlopen(self.url + '/' + name + args,data=kwargs) as r:
                        return json_deserialize(json.loads(str(r.read(),'utf8')))
                except urllib.error.HTTPError as ex:
                    logging.error(str(ex.read(),'utf8'))
                    raise ex
            fn = post_fn
        else:
            raise Exception("Method must start with either 'get_' or 'post_'")

        return fn
