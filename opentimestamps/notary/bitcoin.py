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

import jsonrpc
import struct

from opentimestamps.notary import Signature,SignatureVerificationError
from opentimestamps.crypto import sha256d
from opentimestamps.dag import Hash

from opentimestamps._internal import hexlify,unhexlify

bitcoin_header_format = struct.Struct("<i 32s 32s I 4s I")

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
    @property
    def method(self):
        return 'bitcoin'

    @property
    def timestamp(self):
        return bitcoin_header_format.unpack(self.digest)[3] + BITCOIN_TIMESTAMP_OFFSET

    def __init__(self, method='bitcoin', **kwargs):
        super().__init__(method=method, **kwargs)

    def validate(self, context=None):
        assert context is not None

        block_hash = sha256d(self.digest)

        try:
            proxy = context.bitcoin_proxy[self.identity]
        except KeyError:
            rpc_url = context.bitcoin_rpc_url[self.identity]
            proxy = jsonrpc.ServiceProxy(rpc_url)
            context.bitcoin_proxy[self.identity] = proxy

        try:
            block = proxy.getblock(hexlify(block_hash[::-1]))
        except jsonrpc.JSONRPCException as err:
            # import pdb; pdb.set_trace()
            raise err

        if serialize_block_header(block) != self.digest:
            raise SignatureVerificationError('block not equal to serialized_block')

        return True

def create_checkmultisig_tx(tx_in,m,value,pubkeys,proxy):
    assert 0 < m < len(pubkeys) <= 16

    pubkeys = [unhexlify(pubkey) for pubkey in pubkeys]

    # Create a transaction with no outputs
    partial_tx = unhexlify(proxy.createrawtransaction(tx_in,{}).encode('utf8'))

    scriptSig = b''

    scriptSig += bytes([80 + m])

    for pubkey in pubkeys:
        scriptSig += bytes([len(pubkey)])
        scriptSig += pubkey

    scriptSig += bytes([80 + len(pubkeys)])
    scriptSig += b'\xae'

    return partial_tx[:-5] + b'\x01' + struct.pack('<Q',int(value*100000000)) + bytes([len(scriptSig)]) + scriptSig + partial_tx[-4:]

def calc_p2sh_proof_address(digest,pubkey,proxy):
    inserted_digest = digest
    nonce = 0

    p2sh = None
    while p2sh is None:
        digest_pubkey = '02' + hexlify(inserted_digest)
        try:
            p2sh = proxy.createmultisig(1, [pubkey, digest_pubkey])
        except jsonrpc.JSONRPCException as ex:
            nonce += 1
            inserted_digest = sha256d(digest + chr(nonce))
    print(nonce)
    print(p2sh)


def insert_p2sh_proof(digest,change_addr,proxy,tx_amount=0.1,tx_fee=0.0005):
    assert len(digest) == 32

    assert proxy.validateaddress(change_addr)["ismine"]
    pubkey = proxy.validateaddress(change_addr)["pubkey"]


    tx_out_hash = proxy.sendtoaddress(p2sh["address"],tx_amount)

    # While we know the tx_out transaction to spend from, we don't know what
    # vout number we need to use. Figure that out.
    raw_tx_out = proxy.getrawtransaction(tx_out_hash)
    tx_out = proxy.decoderawtransaction(raw_tx_out)

    voutnum = None
    scriptPubKey = None
    for vout in tx_out["vout"]:
        if p2sh["address"] in vout["scriptPubKey"]["addresses"]:
            voutnum = vout["n"]
            scriptPubKey = vout["scriptPubKey"]["hex"]
            break
    assert voutnum is not None

    print("voutnum",voutnum)

    # Create the tx spending what we sent to the p2sh addr.
    raw_spend_tx = proxy.createrawtransaction(
            [{"txid":tx_out_hash,"vout":voutnum}],
            {change_addr:tx_amount - tx_fee})

    privkey = proxy.dumpprivkey(change_addr)
    raw_spend_tx = proxy.signrawtransaction(raw_spend_tx,
            [{"txid":tx_out_hash,"vout":voutnum,
                "redeemScript":p2sh["redeemScript"],
                "scriptPubKey":scriptPubKey}],
            [privkey])

    print('sending',raw_spend_tx)

    print(proxy.sendrawtransaction(raw_spend_tx["hex"]))

def find_digest_in_block(digest,block_hash,proxy):
    block = proxy.getblock(hexlify(block_hash).decode("utf8"))

    path = []

    tx_num = None
    tx_hash = None
    raw_tx = None
    for (i,tx_hash) in enumerate(block['tx']):
        tx_hash = unhexlify(tx_hash.encode("utf8"))
        try:
            raw_tx = unhexlify(proxy.getrawtransaction(hexlify(tx_hash).decode("utf8")).encode("utf8"))
        except jsonrpc.JSONRPCException as err:
            if err.error['code'] == -5:
                continue
            else:
                raise err
        if digest in raw_tx:
            # Split the raw_tx bytes up to create the Hash inputs. Keep in mind
            # that digest might be present in the transaction more than once.
            inputs = []
            raw_tx_left = raw_tx
            while raw_tx_left:
                j = raw_tx_left.find(digest)
                if j >= 0:
                    inputs.append(raw_tx_left[0:j])
                    inputs.append(digest)
                    raw_tx_left = raw_tx_left[j+len(digest):]
                else:
                    inputs.append(raw_tx_left)
                    raw_tx_left = ''
            path.append(Hash(inputs=inputs, algorithm="sha256d"))
            tx_num = i
            break

    if tx_num is None:
        return None

    assert sha256d(raw_tx)[::-1] == tx_hash

    # Rebuild the merkle tree and in the process collect all the leaves
    # required to go from our tx to the root of he tree.
    #
    # This could probably be optimized, but whatever.
    next_leaf_num = tx_num
    hashes = [unhexlify(tx.encode("utf8"))[::-1] for tx in block['tx']]
    while len(hashes) > 1:
        # Bitcoin duplicates the last hash to make the length even.
        if len(hashes) % 2:
            hashes.append(hashes[-1])

        newhashes = []
        for i in range(0,len(hashes),2):
            newhashes.append(sha256d(hashes[i] + hashes[i+1]))

            if i == next_leaf_num:
                path.append(Hash(inputs=(hashes[i],hashes[i+1]), algorithm="sha256d"))
                next_leaf_num = len(newhashes)-1
            elif i+1 == next_leaf_num:
                path.append(Hash(inputs=(hashes[i],hashes[i+1]), algorithm="sha256d"))
                next_leaf_num = len(newhashes)-1
        hashes = newhashes

    # Finally add the block header itself.
    identity = 'mainnet'
    if proxy.getinfo()['testnet']:
        # FIXME: do we need some way to determine what version of testnet?
        identity = 'testnet'

    raw_block_header = serialize_block_header(block)
    assert hashes[0] == raw_block_header[36:68]
    path.append(
            Verify(inputs=(raw_block_header[0:36], hashes[0], raw_block_header[68:]),
                 method="bitcoin", identity=identity))

    return path

if None:
    proxy = jsonrpc.ServiceProxy("http://pete:CYiDf0OQZD@127.0.0.1:8332")

    digest = sha256d(unhexlify('13249541def3c688e28a32da9a6f39e2c68442db'))
    change_addr = 'miDvz1MnDquvMnSfQ8rwTDVbdckfdCCpTn'

    #insert_p2sh_proof(sha256d(unhexlify(digest)), change_addr, proxy)

    #calc_p2sh_proof_address(sha256d(unhexlify(digest)), '03CEE6A0243E768476AC641EF307D575A6EE8F80B15396093A72A1E496E6D58117', proxy)

    find_digest_in_block(digest,unhexlify('00000000000001f1732f7047b2cfc2aa2f898eb97f42d9f853643fc2636fa842'),proxy)
