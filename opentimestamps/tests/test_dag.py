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

import unittest
import io
import json

from ..op import Digest,Hash
from ..dag import *

class TestDag(unittest.TestCase):
    # TODO: we need a Dag conformance test basically, one that all Dag
    # implementations must pass.
    #
    # Actually, the same applies for Digest, Hash and Verify
    #
    # TODO: also, add test to ensure _swap_input_obj swaps all inputs, even if
    # the same object is presence multiple times.
    def test_in_operator(self):
        dag = Dag()

        self.assertFalse(b'' in dag)
        self.assertFalse(b'd' in dag)
        self.assertFalse(Digest(digest=b'd') in dag)

        d = dag.add(Digest(digest=b'd'))

        self.assertTrue(b'd' in dag)
        self.assertTrue(d in dag)

        d2 = Digest(digest=b'd')
        self.assertTrue(d2 in dag)

        self.assertFalse(b'' in dag)


    def test_getitem_operator(self):
        dag = Dag()

        with self.assertRaises(KeyError):
            dag[1]
        with self.assertRaises(KeyError):
            dag[b'']
        with self.assertRaises(KeyError):
            dag[Digest(digest=b'd')]

        d = dag.add(Digest(digest=b'd'))

        self.assertIs(dag[d],d)

        d2 = Digest(digest=b'd')
        self.assertIs(dag[d2],d)


    def test_dependencies(self):
        dag = Dag()

        self.assertTrue(len(tuple(dag)) == 0)

        # Basic insertion
        d1a = Digest(digest=b'd1')
        d1 = dag.add(d1a)
        self.assertEqual(dag[d1a],d1)

        h_not_in_dag = Hash(d1)
        self.assertEqual(dag[d1a],d1)

        # does not change d1 dependencies
        self.assertEqual(len(dag.dependents[d1]),0)

        # inserted a digest identical to h1
        d2 = dag.add(Digest(digest=h_not_in_dag))
        self.assertEqual(dag[d2],d2)

        # recreate as a more interesting object
        h_in_dag = dag.add(Hash(d1))
        self.assertEqual(h_in_dag,d2)
        self.assertEqual(dag[d2],h_in_dag)

        # d1 now marks h_in_dag as a dependency
        self.assertIn(h_in_dag,dag.dependents[d1])

        h2 = dag.add(Hash(h_in_dag,d1))
        self.assertIn(h2,dag.dependents[d1])
        self.assertIn(h2,dag.dependents[h_in_dag])


    def test_path(self):
        n = 100
        dag = Dag()
        def r(start,dest,expected_path):
            def tuple_or_none(v):
                if v is None:
                    return v
                else:
                    return tuple(v)
            self.assertEqual(
                    tuple_or_none(dag.path(start,dest)),
                    tuple_or_none(expected_path))

        # Create a linked chain of digests
        chain = [Hash(b'')]
        for i in range(1,n):
            chain.append(Hash(chain[i - 1]))

        r(chain[0],chain[0],[chain[0]])
        r(chain[0],chain[1],None)


        # Add some of the chain back in.
        dag.add(chain[0])
        r(chain[0],chain[1],None)
        dag.add(chain[1])
        r(chain[0],chain[1],(chain[1],))
        r(chain[0],chain[2],None)

        # Add the rest
        for i in range(2,n):
            dag.add(chain[i])

        r(chain[0],chain[n-1],chain[1:])
        r(chain[n-1],chain[0],None)


class Test_build_merkle_tree(unittest.TestCase):
    def test(self):
        def t(n,algorithm=None):
            dag = Dag()
            parents = [Digest(digest=bytes(str(i),'utf8')) for i in range(0,n)]

            tree = build_merkle_tree(parents,algorithm=algorithm)

            dag.update(parents)
            dag.update(tree)

            # The whole tree has a path to the tree child.
            max_path = 0
            for d in tree:
                path = tuple(dag.path(d,tree[-1]))
                self.assertFalse(path is None)
                self.assertTrue(len(path) > 0)
                max_path = max(max_path,len(path))

            # Parents have paths to the tree child
            min_path = 2**32
            avg_path = 0
            for d in parents:
                path = tuple(dag.path(d,tree[-1]))
                self.assertFalse(path is None)
                self.assertTrue(len(path) > 0)
                avg_path += len(path)
                min_path = min(len(path),min_path)
                max_path = max(max_path,len(path))

            # Check path lengths are all reasonable
            from math import log
            avg_path /= float(len(parents))
            expected_path = log(n,2)
            self.assertLess(max_path,expected_path+1)
            self.assertGreater(min_path,expected_path/2)
            self.assertTrue(expected_path - 1 < avg_path < expected_path + 1)

        with self.assertRaises(ValueError):
            build_merkle_tree(())

        d = Digest(digest=b'd')
        self.assertSequenceEqual(build_merkle_tree((d,)),(d,))

        for i in (3,4,5,10,21,64,513):
            t(i)
