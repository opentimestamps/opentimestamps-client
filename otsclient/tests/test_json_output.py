import unittest
import io
from types import SimpleNamespace
from unittest.mock import patch

from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from otsclient import cmds


class _HashOp:
    HASHLIB_NAME = "sha256"
    DIGEST_LENGTH = 32


class _FakeArgs(SimpleNamespace):
    pass


class _FakeProxy:
    def getblockcount(self):
        return 900000

    def getblockhash(self, height):
        return b"\x11" * 32

    def getblockheader(self, blockhash):
        return {"merkleroot": "00" * 32}


class TestJsonOutput(unittest.TestCase):
    def test_timestamp_to_json_serializes_pending_attestation(self):
        t = Timestamp(b"\x00" * 32)
        t.attestations = {PendingAttestation("https://calendar.example")}

        payload = cmds.timestamp_to_json(t)

        self.assertEqual(payload["attestation_count"], 1)
        self.assertEqual(payload["attestations"][0]["type"], "PendingAttestation")
        self.assertEqual(payload["attestations"][0]["status"], "pending")

    def test_detached_timestamp_to_json_includes_digest_and_tree(self):
        t = Timestamp(b"\xaa" * 32)
        t.ops.add(OpAppend(b"\x01"))
        detached = DetachedTimestampFile(_HashOp(), t)

        payload = cmds.detached_timestamp_to_json(detached)

        self.assertEqual(payload["hash_algorithm"], "sha256")
        self.assertEqual(payload["file_digest"], "aa" * 32)
        self.assertIn("tree", payload)

    def test_verify_timestamp_json_reports_pending(self):
        t = Timestamp(b"\x00" * 32)
        t.attestations = {PendingAttestation("https://calendar.example")}
        args = _FakeArgs(use_bitcoin=False, calendar_urls=[], wait=False)

        with patch("otsclient.cmds.upgrade_timestamp", lambda timestamp, args: None):
            payload = cmds.verify_timestamp_json(t, args)

        self.assertEqual(payload["status"], "pending")
        self.assertFalse(payload["verified"])

    def test_verify_timestamp_json_reports_verified_bitcoin_attestation(self):
        t = Timestamp(b"\x00" * 32)
        att = BitcoinBlockHeaderAttestation(123)
        t.attestations = {att}
        args = _FakeArgs(
            use_bitcoin=True,
            calendar_urls=[],
            wait=False,
            setup_bitcoin=lambda: _FakeProxy(),
        )

        with patch("otsclient.cmds.upgrade_timestamp", lambda timestamp, args: None):
            with patch.object(
                BitcoinBlockHeaderAttestation,
                "verify_against_blockheader",
                lambda self, msg, block_header: 1234567890,
            ):
                payload = cmds.verify_timestamp_json(t, args)

        self.assertEqual(payload["status"], "verified")
        self.assertTrue(payload["verified"])
        self.assertEqual(payload["attestations"][0]["height"], 123)

    def test_verify_command_json_exits_pending_with_code_2(self):
        t = Timestamp(b"\xaa" * 32)
        detached = DetachedTimestampFile(_HashOp(), t)
        timestamp_fd = io.BytesIO(b"")
        timestamp_fd.name = "dummy.ots"
        args = _FakeArgs(
            timestamp_fd=timestamp_fd,
            hex_digest="aa" * 32,
            target_fd=None,
            json=True,
        )

        with patch("otsclient.cmds.DetachedTimestampFile.deserialize", return_value=detached):
            with patch(
                "otsclient.cmds.verify_timestamp_json",
                return_value={"status": "pending", "verified": False, "attestations": []},
            ):
                with self.assertRaises(SystemExit) as exc:
                    cmds.verify_command(args)

        self.assertEqual(exc.exception.code, cmds.EXIT_VERIFY_PENDING)

    def test_verify_command_json_exits_failed_with_code_1(self):
        t = Timestamp(b"\xaa" * 32)
        detached = DetachedTimestampFile(_HashOp(), t)
        timestamp_fd = io.BytesIO(b"")
        timestamp_fd.name = "dummy.ots"
        args = _FakeArgs(
            timestamp_fd=timestamp_fd,
            hex_digest="aa" * 32,
            target_fd=None,
            json=True,
        )

        with patch("otsclient.cmds.DetachedTimestampFile.deserialize", return_value=detached):
            with patch(
                "otsclient.cmds.verify_timestamp_json",
                return_value={"status": "failed", "verified": False, "attestations": []},
            ):
                with self.assertRaises(SystemExit) as exc:
                    cmds.verify_command(args)

        self.assertEqual(exc.exception.code, cmds.EXIT_VERIFY_FAILED)

    def test_verify_command_json_exits_manual_check_required_with_code_2(self):
        t = Timestamp(b"\xaa" * 32)
        detached = DetachedTimestampFile(_HashOp(), t)
        timestamp_fd = io.BytesIO(b"")
        timestamp_fd.name = "dummy.ots"
        args = _FakeArgs(
            timestamp_fd=timestamp_fd,
            hex_digest="aa" * 32,
            target_fd=None,
            json=True,
        )

        with patch("otsclient.cmds.DetachedTimestampFile.deserialize", return_value=detached):
            with patch(
                "otsclient.cmds.verify_timestamp_json",
                return_value={
                    "status": "manual_check_required",
                    "verified": False,
                    "attestations": [],
                },
            ):
                with self.assertRaises(SystemExit) as exc:
                    cmds.verify_command(args)

        self.assertEqual(exc.exception.code, cmds.EXIT_VERIFY_PENDING)
