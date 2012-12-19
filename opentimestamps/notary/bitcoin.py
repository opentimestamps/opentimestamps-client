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

import logging
import struct

import opentimestamps._bitcoinrpc as btcrpc

from opentimestamps.notary import Signature,SignatureVerificationError
from opentimestamps.crypto import sha256d
from opentimestamps.dag import Hash
from opentimestamps.notary import register_signature_class

from opentimestamps._internal import hexlify,unhexlify

bitcoin_header_format = struct.Struct("<i 32s 32s I 4s I")

def setup_rpc_proxy(identity, context):
    if not hasattr(context,'bitcoin_proxy'):
        context.bitcoin_proxy = {}

    if not identity in context.bitcoin_proxy:
        section = 'bitcoin'
        if identity == 'testnet':
            section = 'bitcoin-testnet'

        rpc_url = None
        if context.config[section]['use_bitcoin_conf']:
            bitcoin_conf = {'rpcport':'8332',
                            'rpcconnect':'localhost'}

            import os
            conf_path = os.path.expanduser(context.config[section]['use_bitcoin_conf'])
            for line in open(conf_path,'r'):
                (key,value) = line.split('=')
                key = key.strip()
                value = value.strip()
                bitcoin_conf[key] = value

            rpc_url = 'http://{}:{}@{}:{}'.format(\
                    bitcoin_conf['rpcuser'],
                    bitcoin_conf['rpcpassword'],
                    bitcoin_conf['rpcconnect'],
                    bitcoin_conf['rpcport'])
        else:
            rpc_url = context.config[section]['rpc_url']

        logging.debug('Opening bitcoin rpc proxy: {}'.format(rpc_url))
        proxy = btcrpc.ServiceProxy(rpc_url)
        context.bitcoin_proxy[identity] = proxy

    return context.bitcoin_proxy[identity]

def serialize_block_header(block):
    """Serialize a block header from the RPC interface"""
    return bitcoin_header_format.pack(
        block['version'],
        unhexlify(block['previousblockhash'])[::-1],
        unhexlify(block['merkleroot'])[::-1],
        block['time'],
        unhexlify(block['bits'])[::-1],
        block['nonce'])

# Assuming network adjusted time is correct, thus it + 2 hours is safe.
BITCOIN_TIMESTAMP_OFFSET = 2*60*60

@register_signature_class
class BitcoinSignature(Signature):
    """Bitcoin signature

    A Bitcoin signature is itself just a block header. A practical use of the
    signature requires a set of ops that recreate the Bitcoin merkle tree
    algorithm leading up to the merkleroot in the header.

    Validation consists of re-doing the sha256d operation to get a block hash,
    asking a trusted Bitcoin node if that hash is in the applicable blockchain,
    and finally checking that the block that trusted Bitcoin node matches the
    block saved in the signature exactly.

    FIXME: does getblock ever return orphans?
    """
    method = 'bitcoin'

    @property
    def timestamp(self):
        return bitcoin_header_format.unpack(self.digest)[3] + BITCOIN_TIMESTAMP_OFFSET

    def __init__(self, method='bitcoin', **kwargs):
        super().__init__(method=method, **kwargs)

    def verify(self, context=None):
        assert context is not None

        block_hash = sha256d(self.digest)

        proxy = setup_rpc_proxy(self.identity, context)

        try:
            block = proxy.getblock(hexlify(block_hash[::-1]))
        except btcrpc.JSONRPCException as err:
            # import pdb; pdb.set_trace()
            raise err

        if serialize_block_header(block) != self.digest:
            raise SignatureVerificationError('block not equal to serialized_block')

        return True
