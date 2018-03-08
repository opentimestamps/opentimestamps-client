import unittest
import os
from opentimestamps.core.op import OpSHA256, MsgValueError
from otsclient.git import hash_signed_commit


class TestGit(unittest.TestCase):

    def test_hash_signed_commit(self):
        def hash_signed_commit_old(git_commit, gpg_sig):
            return OpSHA256()(OpSHA256()(git_commit) + OpSHA256()(gpg_sig))
        for i in range(0, 1000):
            random_git_commit = os.urandom(i)
            random_gpg_sig = os.urandom(i)
            self.assertEqual(hash_signed_commit_old(random_git_commit, random_gpg_sig),
                             hash_signed_commit(random_git_commit, random_gpg_sig))

        self.assertEqual(hash_signed_commit_old(b'', b''), hash_signed_commit(b'', b''))

        self.assertRaises(MsgValueError, hash_signed_commit_old, b'0'*4097, b'')  # old version raises
        self.assertIsNotNone(hash_signed_commit(b'0'*4097, b''))  # new version does not

        self.assertTrue(True)
