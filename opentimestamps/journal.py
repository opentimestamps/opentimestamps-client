# Copyright (C) 2012-2013 Peter Todd <pete@petertodd.org>
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution and at http://opentimestamps.org
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

from opentimestamps.dag import Op,Digest,Hash,Dag

class AppendOnlyIndexedList(list):
    """Append-only list subclass with an efficient .index() method"""
    def __init__(self, iterable=()):
        super().__init__()
        self._index = {}
        for i in iterable:
            self.append(i)

    def remove(self, value):
        raise NotImplementedError
    def pop(self, index):
        raise NotImplementedError

    def append(self, obj):
        super().append(obj)
        self._index[obj] = len(self) - 1

    def index(self, obj):
        if obj not in self._index:
            raise ValueError("%r is not in list" % obj)
        else:
            return self._index[obj]

    def __contains__(self, obj):
        return obj in self._index


class JournalNormalizationRequiredError(Exception):
    pass


class Journal:
    """Link digests together

    A journal is a set of digests that are linked together in some way.
    Journals support a closure() operation, which returns a single digest such
    that every digest added to the journal can be linked to the closure digest
    with a set of operations.

    """
    def __init__(self):
        raise NotImplementedError

    def closure(self):
        """Return the current closure digest"""
        raise NotImplementedError

    def normalize_digest(self, digest):
        """Normalize a digest into the form supported by the journal

        Some journals only accept digests with a specific length for
        efficiency.

        Returns a the list of ops required to convert your digest into the
        supported form. This list will be empty if no coercion is required.
        """
        return ()

    def _add(self, digest):
        raise NotImplementedError

    def add(self, digest, normalize=True):
        """Add a digest to the journal

        Returns a path whose first item is your digest, possibly with added
        metadata, and the last item is a op guaranteed to be in the journals
        digests.

        Adding a digest twice is always a no-op.

        normalize - If false, digest is not normalized first. A
                    JournalNormalizationRequiredError will be raised if the
                    digest needs normalization.
        """
        r = []
        normalize_ops = self.normalize_digest(digest)

        if normalize and normalize_ops:
            r.append(digest)
            r.extend(normalize_ops)
            digest = r[-1]
        elif not normalize and normalize_ops:
            if self.normalize_digest(digest):
                raise JournalNormalizationRequiredError('Digest requires normalization; length not supported')
        r.extend(self._add(digest))
        return r


class LinearJournal(Journal):
    """Simple linear-linked journal"""

    def __init__(self, hash_algorithm='sha256', digests=None, closures=None):
        self.hash_algorithm = hash_algorithm

        if digests is None:
            digests = AppendOnlyIndexedList()
        self.digests = digests

        if closures is None:
            closures = AppendOnlyIndexedList()
        self.closures = closures


    def _add(self, digest):
        if digest in self.digests:
            return (digest,)
        self.digests.append(digest)

        if self.closures:
            self.closures.append(Hash(digest, self.closures[-1], algorithm=self.hash_algorithm))
        else:
            # Special case for the first digest in the journal
            self.closures.append(Hash(digest, algorithm=self.hash_algorithm))

        return (digest,)


    def closure(self):
        return self.closures[-1]

    def path(self, digest, closure):
        if digest not in self.digests or closure not in self.closures:
            return None

        digest_idx = self.digests.index(digest)
        closure_idx = self.closures.index(closure)

        if digest_idx > closure_idx:
            return None

        return self.closures[digest_idx:closure_idx+1]


class MerkleJournal(Journal):
    """Link digests together

    See docs/merkle_mountain_range.md for how digests are linked.
    """
    def __init__(self, hash_algorithm='sha256', metadata_url='', journal_uuid='', digests=None, closures=None):
        self.metadata_url = metadata_url
        self.journal_uuid = journal_uuid

        if digests is None:
            digests = AppendOnlyIndexedList()
        self.digests = digests

        if closures is None:
            closures = {}
        self.closures = closures

        assert len(self.digests) >= len(self.closures.keys())

        def Hash_constructor(*args, **kwargs):
            return Hash(*args, algorithm=hash_algorithm, **kwargs)
        self._Hash = Hash_constructor


    # Height means at that index the digest represents 2**h digests. Thus
    # height for submitted is 0

    @classmethod
    def get_mountain_peak_indexes(cls, digests_len):
        """Return the indexes of the peaks of the mountains, lowest to highest, for a digests list of a given length.

        The lowest mountain will the the first element, the highest the last.
        """
        # Basically, start at the last index, and walk backwards, skipping over
        # how many elemenets would be in a tree of the height that the index
        # position has.
        r = []
        idx = digests_len - 1
        while idx >= 0:
            r.append(idx)
            idx -= 2**(cls.height_at_idx(idx)+1)-1
        return r


    def _build_merkle_tree(self, parents, _accumulator=None):
        """Build a merkle tree, deterministicly

        parents - iterable of all the parents you want in the tree.

        Returns an iterable of all the intermediate digests created, and the
        final child, which will be at the end. If parents has exactly one item
        in it, that parent is the merkle tree child.
        """

        # This is a copy of opentimestamps.dag.build_merkle_tree, included here
        # because unlike that function this one has to be deterministic, and we
        # don't want changes there to impact what we're doing here.

        accumulator = _accumulator
        if accumulator is None:
            accumulator = []
            parents = iter(parents)

        next_level_starting_idx = len(accumulator)

        while True:
            try:
                p1 = next(parents)
            except StopIteration:
                # Even number of items, possibly zero.
                if len(accumulator) == 0 and _accumulator is None:
                    # We must have been called with nothing at all.
                    raise ValueError("No parent digests given to build a merkle tree from""")
                elif next_level_starting_idx < len(accumulator):
                    return self._build_merkle_tree(iter(accumulator[next_level_starting_idx:]),
                                                   _accumulator=accumulator)
                else:
                    return accumulator

            try:
                p2 = next(parents)
            except StopIteration:
                # We must have an odd number of elements at this level, or there
                # was only one parent.
                if len(accumulator) == 0 and _accumulator is None:
                    # Called with exactly one parent
                    return (p1,)
                elif next_level_starting_idx < len(accumulator):
                    accumulator.append(p1)
                    # Note how for an odd number of items we reverse the list. This
                    # switches the odd item out each time. If we didn't do this the
                    # odd item out on the first level would effectively rise to the
                    # top, and have an abnormally short path. This also makes the
                    # overall average path length slightly shorter by distributing
                    # unfairness.

                    # FIXME: is that iter really needed?
                    return self._build_merkle_tree(iter(reversed(accumulator[next_level_starting_idx:])),
                                                   _accumulator=accumulator)
                else:
                    return accumulator

            h = self._Hash(p1,p2)
            accumulator.append(h)


    def get_peak_closure(self, digests_len=None):
        if not digests_len:
            digests_len = len(self.digests)
        peaks = self.get_mountain_peak_indexes(digests_len)

        peaks = [self.digests[peak] for peak in peaks]

        merkle_peak_ops = self._build_merkle_tree(peaks)

        return merkle_peak_ops

    def closure(self):
        return self.get_peak_closure()[-1]

    @classmethod
    def height_at_idx(cls, idx):
        """Find the height of the mountain at a given peaks index"""

        # Basically convert idx to the count of items left in the tree. Then
        # take away successively smaller trees, from the largest possible to
        # the smallest, and keep track of what height the last tree taken away
        # was. Height being defined as the tree with 2**(h+1)-1 *total* digests.
        last_h = None
        count = idx + 1
        while count > 0:
            for h in reversed(range(0,64)):
                assert h >= 0
                if 2**(h+1)-1 <= count:
                    last_h = h
                    count -= 2**(h+1)-1
                    break
        return last_h

    @classmethod
    def peak_child(cls, idx):
        """Return the index of the child for a peak"""
        # Two possibilities: either we're next to the peak
        idx_height = cls.height_at_idx(idx)
        if idx_height+1 == cls.height_at_idx(idx+1):
            return idx+1
        else:
            # Or the peak is way off to the right
            return idx + 2**(idx_height+1)


    def _add(self, digest):
        """Add a digest"""
        assert self.height_at_idx(len(self.digests))==0

        if digest in self.digests:
            return (digest,) # FIXME: metadata?

        self.digests.append(digest)

        # Build up the mountains
        while self.height_at_idx(len(self.digests)) != 0:
            # Index of the hash that will be added
            idx = len(self.digests)
            h = self._Hash(self.digests[idx - 1],
                           self.digests[idx - 2**self.height_at_idx(idx)])

            self.digests.append(h)

        # Compute the closure at this length and add the current length to the
        # index.
        self.closures[self.closure()] = len(self.digests)

        return (digest,)


    def path(self, digest, closure):
        r = []

        if digest not in self.digests or closure not in self.closures:
            return None

        digest_idx = self.digests.index(digest)
        digests_len = self.closures[closure]

        if digests_len <= digest_idx:
            # Closure was created before digest was added
            return None

        # Get the set of all peak indexes this verification was made over
        target_peaks = self.get_mountain_peak_indexes(digests_len)

        # From the digest_op's index, climb the mountain until we intersect one
        # of the target peaks
        path = []
        while digest_idx not in target_peaks:
            digest_idx = self.peak_child(digest_idx)
            if digest_idx > len(self.digests):
                import pdb; pdb.set_trace()
            path.append(self.digests[digest_idx])

        # Extend that path with the closure of those peaks
        path.extend(self.get_peak_closure(digests_len))

        # Prune the path so we only return the minimum ops required.
        dag = Dag()
        dag.update(path)
        path = dag.path(digest, closure)
        assert path is not None

        return path
