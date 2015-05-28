# Copyright (C) 2015 The python-opentimestamps developers
#
# This file is part of python-opentimestamps.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from bitcoin.core import Hash
from opentimestamps.core import PathOp_SHA256, Path

def path_from_msg_to_txid(msg, tx):
    serialized = tx.serialize()

    i = serialized.find(msg)

    assert(i >= 0)

    prefix = serialized[:i]
    suffix = serialized[i+len(msg):]

    return Path([PathOp_SHA256(prefix, suffix), PathOp_SHA256(b'',b'')])

def path_from_txid_to_merkleroot(txid, blk):
    merkle_tree = [tx.GetHash() for tx in blk.vtx]

    path = []

    size = len(merkle_tree)
    j = 0

    path_top = txid
    while size > 1:
        new_path_top = None
        for i in range(0, size, 2):
            i2 = min(i+1, size-1)
            merkle_tree.append(Hash(merkle_tree[j+i] + merkle_tree[j+i2]))

            if new_path_top is None:
                if merkle_tree[j+i] == path_top:
                    path.append(PathOp_SHA256(b'', merkle_tree[j+i2]))
                    path.append(PathOp_SHA256(b'', b''))
                    new_path_top = merkle_tree[-1]

                    assert(Path(path)(txid) == new_path_top)

                elif merkle_tree[j+i2] == path_top:
                    path.append(PathOp_SHA256(merkle_tree[j+i], b''))
                    path.append(PathOp_SHA256(b'', b''))
                    new_path_top = merkle_tree[-1]

                    assert(Path(path)(txid) == new_path_top)

        assert new_path_top is not None
        path_top = new_path_top

        j += size
        size = (size + 1) // 2

    r = Path(path)

    assert r(txid) == blk.calc_merkle_root()

    return r
