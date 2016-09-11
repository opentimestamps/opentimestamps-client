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

"""Git integration"""

import dbm
import git
import io
import os

from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile, make_merkle_tree
from opentimestamps.core.op import OpAppend, OpPrepend, OpSHA256

class GitTreeTimestamper:
    """Efficient, privacy-preserving, git tree timestamping

    Unfortunately, the way git calculates commit hashes is less than ideal for
    timestamping. The first problem is of course the fact that they're SHA1
    hashes: still good enough for timestamping, but all the same a dubious
    choice of hash algorithm.

    The second problem is more subtle: What if I want to extract a timestamp
    proof for an individual file in the commit? Since git hashes tree objects
    as linear blobs of data, the proof will contain a significant amount of
    extraneous metadata about files other than the one you want - inefficient
    and a privacy risk.

    This class solves these problems by recursively re-hashing a git tree and all blobs
    in it with SHA256, using a cache of previously calculated hashes for
    efficiency. Each git tree is hashed as a merkle tree, allowing paths to
    individual blobs to be extracted efficiently.

    For privacy, we guarantee that given a timestamp for a single item in a
    given tree, an attacker trying to guess the contents of any other item in
    the tree can only do so by brute-forcing all other content in the tree
    simultaneously. We achieve this by deterministically generating nonces for
    each item in the tree based on the item's hash, and the contents of the
    rest of the tree.

    However, note that we do _not_ prevent the attacker from learning about the
    directly structure of the repository, including the number of items in each
    directory.

    """

    def __init__(self, tree, db=None, file_hash_op=OpSHA256(), tree_hash_op=OpSHA256()):
        self.tree = tree

        if db is None:
            os.makedirs(tree.repo.git_dir + '/ots', exist_ok=True)

            # WARNING: change the version number if any of the following is
            # changed; __init__() is consensus-critical!
            db = dbm.open(tree.repo.git_dir + '/ots/tree-hash-cache-v3', 'c')

        self.db = db
        self.file_hash_op = file_hash_op
        self.tree_hash_op = tree_hash_op

        def do_item(item):
            try:
                return (item, Timestamp(db[item.hexsha]))
            except KeyError:
                timestamp = None
                if isinstance(item, git.Blob):
                    timestamp = Timestamp(file_hash_op.hash_fd(item.data_stream[3]))

                elif isinstance(item, git.Tree):
                    stamper = GitTreeTimestamper(item, db=db, file_hash_op=file_hash_op, tree_hash_op=tree_hash_op)
                    timestamp = stamper.timestamp

                elif isinstance(item, git.Submodule):
                    # A submodule is just a git commit hash.
                    #
                    # Unfortunately we're not guaranteed to have the repo
                    # behind it, so all we can do is timestamp that SHA1 hash.
                    #
                    # We do run it through the tree_hash_op to make it
                    # indistinguishable from other things; consider the
                    # degenerate case where the only thing in a git repo was a
                    # submodule.
                    timestamp = Timestamp(tree_hash_op(item.binsha))

                else:
                    raise NotImplementedError("Don't know what to do with %r" % item)

                db[item.hexsha] = timestamp.msg
                return (item, timestamp)

        self.contents = tuple(do_item(item) for item in self.tree)

        if len(self.contents) > 1:
            # Deterministically nonce contents in an all-or-nothing transform. As
            # mentioned in the class docstring, we want to ensure that the the
            # siblings of any leaf in the merkle tree don't give the attacker any
            # information about what else is in the tree, unless the attacker
            # already knows (or can brute-force) the entire contents of the tree.
            #
            # While not perfect - a user-provided persistant key would prevent the
            # attacker from being able to brute-force the contents - this option
            # has the advantage of being possible to calculate deterministically
            # using only the tree itself, removing the need to keep secret keys
            # that can easily be lost.
            #
            # First, calculate a nonce_key that depends on the entire contents of
            # the tree. The 8-byte tag ensures the key calculated is unique for
            # this purpose.
            contents_sum = b''.join(stamp.msg for item, stamp in self.contents) + b'\x01\x89\x08\x0c\xfb\xd0\xe8\x08'
            nonce_key = tree_hash_op.hash_fd(io.BytesIO(contents_sum))

            # Second, calculate per-item nonces deterministically from that key,
            # and add those nonces to the timestamps of every item in the tree.
            #
            # While we usually use 128-bit nonces, here we're using full-length
            # nonces. Additionally, we pick append/prepend pseudo-randomly. This
            # helps obscure the directory structure, as a commitment for a git tree
            # is indistinguishable from a inner node in the per-git-tree merkle
            # tree.
            def deterministically_nonce_stamp(private_stamp):
                nonce1 = tree_hash_op(private_stamp.msg + nonce_key)
                nonce2 = tree_hash_op(nonce1)

                side = OpPrepend if nonce1[0] & 0b1 else OpAppend
                nonce_added = private_stamp.ops.add(side(nonce2))
                return nonce_added.ops.add(tree_hash_op)

            nonced_contents = (deterministically_nonce_stamp(stamp) for item, stamp in self.contents)

            # Note how the current algorithm, if asked to timestamp a tree
            # with a single thing in it, will return the hash of that thing
            # directly. From the point of view of just commiting to the data that's
            # perfectly fine, and probably (slightly) better as it reveals a little
            # less information about directory structure.
            self.timestamp = make_merkle_tree(nonced_stamp for nonced_stamp in nonced_contents)

        elif len(self.contents) == 1:
            # If there's only one item in the tree, the fancy all-or-nothing
            # transform above is just a waste of ops, so use the tree contents
            # directly instead.
            self.timestamp = tuple(self.contents)[0][1]

        else:
            raise AssertionError("Empty git tree")

    def __getitem__(self, path):
        """Get a DetachedTimestampFile for blob at path

        The timestamp object returned will refer to self.timestamp, so
        modifying self.timestamp will modify the timestamp returned.

        If path does not exist, FileNotFound error will be raised.
        If path exists, but is not a blob, ValueError will be raised.
        """
        for item, item_stamp in self.contents:
            if item.path == path:
                if isinstance(item, git.Blob):
                    return DetachedTimestampFile(self.file_hash_op, item_stamp)

                else:
                    raise ValueError("Path %r is not a blob" % item.path)

            elif path.startswith(item.path + '/'):
                if isinstance(item, git.Tree):
                    # recurse
                    tree_stamper = GitTreeTimestamper(item, db=self.db, file_hash_op=self.file_hash_op, tree_hash_op=self.tree_hash_op)
                    tree_stamper.timestamp.merge(item_stamp)
                    return tree_stamper[path]

                else:
                    raise FileNotFoundError("Path %r not found; prefix %r is a blob" % (path, item.path))
        else:
            raise FileNotFoundError("Path %r not found" % path)
