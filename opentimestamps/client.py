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

import configparser
import os

default_conf = {'bitcoin':{'use_bitcoin_conf': '~/.bitcoin/bitcoin.conf',
                           'rpc_url': ''},
                'bitcoin-testnet':{'use_bitcoin_conf': '~/.bitcoin/bitcoin.conf',
                                   'rpc_url': ''}}

class Context:
    """Store of the context the client is working with.

    The main thing this provides is access to what was defined in the config file.
    """

    def __init__(self, config_file=None):
        self.config = configparser.ConfigParser()
        self.config.read_dict(default_conf)
        if config_file is not None:
            self.config.read((os.path.expanduser(config_file),))
