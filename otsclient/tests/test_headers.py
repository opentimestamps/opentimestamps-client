# Copyright (C) 2026 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import hashlib
import os
import tempfile
import unittest
from unittest import mock

import bitcoin
import bitcoin.core
import bitcoin.messages

from otsclient.headers import (
    HeaderArchive,
    HeaderArchiveError,
    HeaderArchiveFormatError,
    HeaderArchiveChainError,
    HeaderArchiveNetworkMismatch,
    BlockHeaderSource,
    LocalArchiveHeaderSource,
    HeaderFetcher,
    BitcoinP2PHeaderFetcher,
    P2PFetcherError,
    P2PProtocolError,
    VerifyCache,
    AutoFetchHeaderSource,
    LocalVerifyCacheHeaderSource,
    bootstrap_archive_from_url,
    build_sidecar_from_heights,
    detect_archive_format,
    _P2PPeerSession,
    _read_p2p_message,
    _parse_headers_body,
    _walk_validate_archive,
    ARCHIVE_MAGIC,
    ARCHIVE_FILE_HEADER_SIZE,
    BLOCK_HEADER_SIZE,
    VERIFY_CACHE_MAGIC,
    VERIFY_CACHE_FILE_HEADER_SIZE,
    VERIFY_CACHE_RECORD_SIZE,
    CHECKPOINTS,
    HeaderNotVerified,
    check_archive_anchors,
    check_archive_anchor,
)


def genesis_header():
    """Return the mainnet genesis block as a CBlockHeader."""
    gb = bitcoin.params.GENESIS_BLOCK
    return gb.get_header() if hasattr(gb, 'get_header') else gb


class _MockHeaderSource(BlockHeaderSource):
    """Test helper: returns headers from a dict of {height: header}."""

    def __init__(self, headers_by_height, fail_for_heights=None):
        self.headers_by_height = dict(headers_by_height)
        self.fail_for_heights = set(fail_for_heights or [])

    def get_header_at_height(self, height):
        if height in self.fail_for_heights:
            raise ConnectionError("simulated failure for height %d" % height)
        if height not in self.headers_by_height:
            raise IndexError("no header at height %d" % height)
        return self.headers_by_height[height]

    def get_block_count(self):
        return max(self.headers_by_height.keys()) if self.headers_by_height else 0


class TestHeaderArchive(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.archive_path = os.path.join(self._tmpdir.name, 'test.headers.bin')

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_create_empty(self):
        """Creating an empty archive writes a 16-byte file header"""
        a = HeaderArchive(self.archive_path)
        a.create('mainnet', 0)
        info = a.info()
        self.assertEqual(info['network'], 'mainnet')
        self.assertEqual(info['start_height'], 0)
        self.assertEqual(info['header_count'], 0)
        self.assertEqual(info['file_size'], ARCHIVE_FILE_HEADER_SIZE)

    def test_create_at_nonzero_start_height(self):
        """Archive can be created starting at an arbitrary height"""
        a = HeaderArchive(self.archive_path)
        a.create('mainnet', 800000)
        _net, start, count = a.read_file_header()
        self.assertEqual(start, 800000)
        self.assertEqual(count, 0)

    def test_create_refuses_overwrite(self):
        """Create on an existing file raises HeaderArchiveError"""
        a = HeaderArchive(self.archive_path)
        a.create('mainnet', 0)
        with self.assertRaises(HeaderArchiveError):
            a.create('mainnet', 0)

    def test_genesis_roundtrip(self):
        """Genesis block appends and reads back identically"""
        a = HeaderArchive(self.archive_path)
        a.create('mainnet', 0)
        genesis = genesis_header()
        a.append_header(genesis)

        info = a.info()
        self.assertEqual(info['header_count'], 1)
        self.assertEqual(info['end_height'], 0)
        self.assertEqual(info['file_size'], ARCHIVE_FILE_HEADER_SIZE + BLOCK_HEADER_SIZE)

        h_back = a.get_header_at_height(0)
        self.assertEqual(h_back.serialize(), genesis.serialize())

    def test_out_of_range_height_raises(self):
        """Asking for a height outside the archive's range raises IndexError"""
        a = HeaderArchive(self.archive_path)
        a.create('mainnet', 0)
        a.append_header(genesis_header())
        with self.assertRaises(IndexError):
            a.get_header_at_height(1)
        with self.assertRaises(IndexError):
            a.get_header_at_height(-1)

    def test_chain_continuity_check(self):
        """Appending a header that does not chain to the previous one fails"""
        a = HeaderArchive(self.archive_path)
        a.create('mainnet', 0)
        a.append_header(genesis_header())

        # A header whose prev_block_hash is all zeros does not chain to genesis
        fake = bitcoin.core.CBlockHeader(
            nVersion=1,
            hashPrevBlock=b'\x00' * 32,
            hashMerkleRoot=b'\x00' * 32,
            nTime=0,
            nBits=0x1d00ffff,
            nNonce=0,
        )
        with self.assertRaises(HeaderArchiveChainError):
            a.append_header(fake)

    def test_pow_check_rejects_invalid_pow(self):
        """A header with nNonce=0 should fail PoW for the genesis difficulty"""
        # Construct a "first block" header that does chain to genesis but has
        # invalid PoW (random nonce that doesn't satisfy the target).
        a = HeaderArchive(self.archive_path)
        a.create('mainnet', 0)
        a.append_header(genesis_header())

        bad_header = bitcoin.core.CBlockHeader(
            nVersion=1,
            hashPrevBlock=genesis_header().GetHash(),
            hashMerkleRoot=b'\x42' * 32,
            nTime=1231469665,
            nBits=0x1d00ffff,
            nNonce=0,  # almost certainly does not satisfy the target
        )
        with self.assertRaises(HeaderArchiveChainError):
            a.append_header(bad_header)

    def test_format_magic_check(self):
        """Reading a file with wrong magic raises HeaderArchiveFormatError"""
        with open(self.archive_path, 'wb') as fd:
            fd.write(b'NOPE' + b'\x00' * (ARCHIVE_FILE_HEADER_SIZE - 4))
        a = HeaderArchive(self.archive_path)
        with self.assertRaises(HeaderArchiveFormatError):
            a.read_file_header()

    def test_format_truncated_body(self):
        """A file whose body isn't a multiple of 80 bytes raises FormatError"""
        a = HeaderArchive(self.archive_path)
        a.create('mainnet', 0)
        # Append 40 bytes of garbage (half a header)
        with open(self.archive_path, 'ab') as fd:
            fd.write(b'\x00' * (BLOCK_HEADER_SIZE // 2))
        with self.assertRaises(HeaderArchiveFormatError):
            a.read_file_header()


class TestLocalArchiveHeaderSource(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.archive_path = os.path.join(self._tmpdir.name, 'test.headers.bin')
        self.archive = HeaderArchive(self.archive_path)
        self.archive.create('mainnet', 0)
        self.archive.append_header(genesis_header())
        self.source = LocalArchiveHeaderSource(self.archive)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_get_header_at_known_height(self):
        """Source returns the same header that was archived"""
        h = self.source.get_header_at_height(0)
        self.assertEqual(h.serialize(), genesis_header().serialize())

    def test_get_header_at_unknown_height_raises(self):
        """Asking for an out-of-range height raises IndexError"""
        with self.assertRaises(IndexError):
            self.source.get_header_at_height(99999999)

    def test_get_block_count(self):
        """Block count reflects the highest stored height"""
        self.assertEqual(self.source.get_block_count(), 0)


class TestHeaderFetcher(unittest.TestCase):

    def setUp(self):
        self.header_a = genesis_header()
        # A second distinct fake header for "disagreement" tests
        self.header_b = bitcoin.core.CBlockHeader(
            nVersion=2,
            hashPrevBlock=b'\x00' * 32,
            hashMerkleRoot=b'\x11' * 32,
            nTime=0, nBits=0x1d00ffff, nNonce=0,
        )

    def test_single_source_pass(self):
        """One source, quorum=1: returns the header unchanged"""
        s = _MockHeaderSource({0: self.header_a})
        f = HeaderFetcher([s], quorum=1)
        out = f.fetch_header(0)
        self.assertEqual(out.serialize(), self.header_a.serialize())

    def test_quorum_agreement(self):
        """Three sources agreeing meet quorum=2"""
        s1 = _MockHeaderSource({0: self.header_a})
        s2 = _MockHeaderSource({0: self.header_a})
        s3 = _MockHeaderSource({0: self.header_a})
        f = HeaderFetcher([s1, s2, s3], quorum=2)
        out = f.fetch_header(0)
        self.assertEqual(out.serialize(), self.header_a.serialize())

    def test_quorum_majority_wins(self):
        """Two sources agree, one disagrees: majority wins at quorum=2"""
        s1 = _MockHeaderSource({0: self.header_a})
        s2 = _MockHeaderSource({0: self.header_a})
        s3 = _MockHeaderSource({0: self.header_b})
        f = HeaderFetcher([s1, s2, s3], quorum=2)
        out = f.fetch_header(0)
        self.assertEqual(out.serialize(), self.header_a.serialize())

    def test_quorum_failure_raises(self):
        """No two sources agree: quorum=2 fails"""
        s1 = _MockHeaderSource({0: self.header_a})
        s2 = _MockHeaderSource({0: self.header_b})
        # A third totally different header
        header_c = bitcoin.core.CBlockHeader(
            nVersion=3,
            hashPrevBlock=b'\x00' * 32,
            hashMerkleRoot=b'\x22' * 32,
            nTime=0, nBits=0x1d00ffff, nNonce=0,
        )
        s3 = _MockHeaderSource({0: header_c})
        f = HeaderFetcher([s1, s2, s3], quorum=2)
        with self.assertRaises(HeaderArchiveError):
            f.fetch_header(0)

    def test_failing_source_does_not_block_quorum(self):
        """One source erroring out shouldn't break quorum if others agree"""
        s1 = _MockHeaderSource({0: self.header_a})
        s2 = _MockHeaderSource({0: self.header_a})
        s3 = _MockHeaderSource({}, fail_for_heights=[0])
        f = HeaderFetcher([s1, s2, s3], quorum=2)
        out = f.fetch_header(0)
        self.assertEqual(out.serialize(), self.header_a.serialize())

    def test_all_sources_failing_raises(self):
        """If all sources fail, the fetcher raises"""
        s1 = _MockHeaderSource({}, fail_for_heights=[0])
        s2 = _MockHeaderSource({}, fail_for_heights=[0])
        f = HeaderFetcher([s1, s2], quorum=1)
        with self.assertRaises(HeaderArchiveError):
            f.fetch_header(0)

    def test_empty_sources_rejected(self):
        """Cannot construct a fetcher with no sources"""
        with self.assertRaises(ValueError):
            HeaderFetcher([], quorum=1)

    def test_invalid_quorum_rejected(self):
        """Quorum must be in 1..len(sources)"""
        s = _MockHeaderSource({0: self.header_a})
        with self.assertRaises(ValueError):
            HeaderFetcher([s], quorum=0)
        with self.assertRaises(ValueError):
            HeaderFetcher([s], quorum=2)


class TestVerifyCache(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self._tmpdir.name, 'verify-cache.bin')
        self.genesis = genesis_header()

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_create_empty(self):
        """Creating a verify cache writes a 16-byte file header"""
        c = VerifyCache(self.cache_path)
        c.create('mainnet')
        net, count = c.read_file_header()
        self.assertEqual(net, 'mainnet')
        self.assertEqual(count, 0)
        self.assertEqual(os.path.getsize(self.cache_path),
                         VERIFY_CACHE_FILE_HEADER_SIZE)

    def test_magic_written(self):
        """File header begins with the OTSV magic bytes"""
        c = VerifyCache(self.cache_path)
        c.create('mainnet')
        with open(self.cache_path, 'rb') as fd:
            self.assertEqual(fd.read(4), VERIFY_CACHE_MAGIC)

    def test_create_refuses_overwrite(self):
        """Create on an existing file raises HeaderArchiveError"""
        c = VerifyCache(self.cache_path)
        c.create('mainnet')
        with self.assertRaises(HeaderArchiveError):
            c.create('mainnet')

    def test_create_unknown_network_rejected(self):
        """Unknown network name raises HeaderArchiveError"""
        c = VerifyCache(self.cache_path)
        with self.assertRaises(HeaderArchiveError):
            c.create('mainnetx')

    def test_add_and_get(self):
        """Round-trip: add a header at a height, get it back"""
        c = VerifyCache(self.cache_path)
        c.create('mainnet')
        c.add(0, self.genesis)
        got = c.get(0)
        self.assertIsNotNone(got)
        self.assertEqual(got.serialize(), self.genesis.serialize())

    def test_get_missing_returns_none(self):
        """Looking up an absent height returns None, not an error"""
        c = VerifyCache(self.cache_path)
        c.create('mainnet')
        self.assertIsNone(c.get(0))
        c.add(0, self.genesis)
        self.assertIsNone(c.get(1))

    def test_iter_records(self):
        """iter_records yields (height, header) in file order"""
        c = VerifyCache(self.cache_path)
        c.create('mainnet')
        c.add(0, self.genesis)
        c.add(42, self.genesis)  # PoW passes; height is just a label here
        records = list(c.iter_records())
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0][0], 0)
        self.assertEqual(records[1][0], 42)
        for _height, header in records:
            self.assertEqual(header.serialize(), self.genesis.serialize())

    def test_add_rejects_invalid_pow(self):
        """A header whose hash doesn't satisfy nBits is rejected"""
        c = VerifyCache(self.cache_path)
        c.create('mainnet')
        bad_header = bitcoin.core.CBlockHeader(
            nVersion=2,
            hashPrevBlock=b'\x00' * 32,
            hashMerkleRoot=b'\x11' * 32,
            nTime=0, nBits=0x1d00ffff, nNonce=0,
        )
        with self.assertRaises(HeaderArchiveChainError):
            c.add(0, bad_header)

    def test_bad_magic_rejected_on_read(self):
        """A file with the wrong magic raises HeaderArchiveFormatError"""
        with open(self.cache_path, 'wb') as fd:
            fd.write(b'XXXX' + b'\x00' * (VERIFY_CACHE_FILE_HEADER_SIZE - 4))
        c = VerifyCache(self.cache_path)
        with self.assertRaises(HeaderArchiveFormatError):
            c.read_file_header()

    def test_truncated_record_rejected(self):
        """A body size that's not a multiple of the record size is rejected"""
        c = VerifyCache(self.cache_path)
        c.create('mainnet')
        # Append a partial record (4 bytes < 84).
        with open(self.cache_path, 'ab') as fd:
            fd.write(b'\x00\x00\x00\x00')
        with self.assertRaises(HeaderArchiveFormatError):
            c.read_file_header()


class TestAutoFetchHeaderSource(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self._tmpdir.name, 'verify-cache.bin')
        self.genesis = genesis_header()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _make_source(self, cache=None, header=None):
        if header is None:
            header = self.genesis
        s = _MockHeaderSource({0: header})
        fetcher = HeaderFetcher([s], quorum=1)
        if cache is None:
            cache = VerifyCache(self.cache_path)
        return AutoFetchHeaderSource(cache, fetcher, 'mainnet', log=False), s

    def test_empty_cache_fetches_and_caches(self):
        """First lookup populates the cache from the fetcher"""
        src, _s = self._make_source()
        out = src.get_header_at_height(0)
        self.assertEqual(out.serialize(), self.genesis.serialize())
        self.assertTrue(os.path.isfile(self.cache_path))
        cache = VerifyCache(self.cache_path)
        cached = cache.get(0)
        self.assertIsNotNone(cached)
        self.assertEqual(cached.serialize(), self.genesis.serialize())

    def test_second_lookup_uses_cache(self):
        """A second lookup at the same height doesn't call the fetcher"""
        cache = VerifyCache(self.cache_path)
        src, mock_source = self._make_source(cache=cache)
        src.get_header_at_height(0)
        # Pop the source's data so a re-fetch would IndexError.
        mock_source.headers_by_height.clear()
        out = src.get_header_at_height(0)
        self.assertEqual(out.serialize(), self.genesis.serialize())

    def test_cache_none_disables_caching(self):
        """cache=None: always fetches, never writes a file"""
        s = _MockHeaderSource({0: self.genesis})
        fetcher = HeaderFetcher([s], quorum=1)
        src = AutoFetchHeaderSource(None, fetcher, 'mainnet', log=False)
        src.get_header_at_height(0)
        self.assertFalse(os.path.isfile(self.cache_path))

    def test_network_mismatch_raises(self):
        """An existing cache for a different network raises"""
        cache = VerifyCache(self.cache_path)
        cache.create('testnet')
        src, _s = self._make_source(cache=cache)
        with self.assertRaises(HeaderArchiveNetworkMismatch):
            src.get_header_at_height(0)

    def test_fetched_bad_pow_raises(self):
        """A fetched header that fails PoW is rejected before caching"""
        bad_header = bitcoin.core.CBlockHeader(
            nVersion=2,
            hashPrevBlock=b'\x00' * 32,
            hashMerkleRoot=b'\x11' * 32,
            nTime=0, nBits=0x1d00ffff, nNonce=0,
        )
        src, _s = self._make_source(header=bad_header)
        with self.assertRaises(HeaderArchiveChainError):
            src.get_header_at_height(0)
        # Cache should not have been created on the bad-PoW path.
        if os.path.isfile(self.cache_path):
            cache = VerifyCache(self.cache_path)
            _net, count = cache.read_file_header()
            self.assertEqual(count, 0)


def _build_headers_message_body(headers):
    """Serialize a list of CBlockHeaders into a P2P headers-message body.

    Each entry is 80 bytes of header followed by a single 0x00 byte
    (transaction-count varint = 0), matching the on-wire format.
    """
    import io
    out = io.BytesIO()
    bitcoin.core.VarIntSerializer.stream_serialize(len(headers), out)
    for h in headers:
        out.write(h.serialize())
        out.write(b'\x00')  # transaction count varint = 0
    return out.getvalue()


def _frame_p2p_message(command, body):
    """Wrap a body in P2P framing (magic + command + length + checksum)."""
    import hashlib
    import struct
    cmd_padded = command + b'\x00' * (12 - len(command))
    length = struct.pack(b'<I', len(body))
    checksum = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    return bitcoin.params.MESSAGE_START + cmd_padded + length + checksum + body


class _FakeSocket:
    """A minimal socket stand-in for testing P2P session logic.

    `recv_script` is a sequence of pre-framed messages the peer will
    "send" back (consumed in order each time the session reads). All
    `sendall()` calls are captured for later inspection.
    """

    def __init__(self, recv_script):
        self.sent = []
        self._recv_buf = b''.join(recv_script)

    def sendall(self, data):
        self.sent.append(data)

    def makefile(self, mode='rb'):
        import io
        return io.BytesIO(self._recv_buf)

    def close(self):
        pass


class TestP2PMessageParsing(unittest.TestCase):

    def test_parse_headers_body_skips_trailing_byte(self):
        """Header bodies on the wire have a 0-byte tx-count after each 80-byte header"""
        # Two distinct, identifiable headers
        h0 = bitcoin.core.CBlockHeader(
            nVersion=1, hashPrevBlock=b'\x00' * 32,
            hashMerkleRoot=b'\x11' * 32, nTime=1, nBits=0x1d00ffff, nNonce=10)
        h1 = bitcoin.core.CBlockHeader(
            nVersion=2, hashPrevBlock=b'\x22' * 32,
            hashMerkleRoot=b'\x33' * 32, nTime=2, nBits=0x1d00ffff, nNonce=20)
        body = _build_headers_message_body([h0, h1])
        parsed = _parse_headers_body(body)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].serialize(), h0.serialize())
        self.assertEqual(parsed[1].serialize(), h1.serialize())

    def test_parse_headers_body_truncated_raises(self):
        """A body shorter than count * 80 bytes is rejected"""
        # Claim 2 headers but include only 40 bytes of payload
        import io
        out = io.BytesIO()
        bitcoin.core.VarIntSerializer.stream_serialize(2, out)
        out.write(b'\x00' * 40)
        with self.assertRaises(P2PProtocolError):
            _parse_headers_body(out.getvalue())

    def test_read_p2p_message_roundtrip(self):
        """Properly framed message decodes to (command, body) with checksum check"""
        import io
        body = b'hello world'
        framed = _frame_p2p_message(b'foo', body)
        f = io.BytesIO(framed)
        cmd, got_body = _read_p2p_message(f)
        self.assertEqual(cmd, b'foo')
        self.assertEqual(got_body, body)

    def test_read_p2p_message_bad_magic_raises(self):
        """Wrong magic bytes raise P2PProtocolError"""
        import io
        framed = b'WRONG' + b'\x00' * 100
        f = io.BytesIO(framed)
        with self.assertRaises(P2PProtocolError):
            _read_p2p_message(f)

    def test_read_p2p_message_bad_checksum_raises(self):
        """Tampered body that no longer matches the framing checksum is rejected"""
        import io
        body = b'original'
        framed = bytearray(_frame_p2p_message(b'foo', body))
        # Flip a byte inside the body (past the 24-byte header)
        framed[30] = framed[30] ^ 0xff
        f = io.BytesIO(bytes(framed))
        with self.assertRaises(P2PProtocolError):
            _read_p2p_message(f)


class TestP2PPeerSession(unittest.TestCase):

    def _genesis_header(self):
        gb = bitcoin.params.GENESIS_BLOCK
        return gb.get_header() if hasattr(gb, 'get_header') else gb

    def test_handshake_completes(self):
        """Session completes version/verack exchange given canned peer responses"""
        # Peer sends: version + verack
        peer_messages = [
            _frame_p2p_message(b'version', bitcoin.messages.msg_version().to_bytes()[24:]),
            _frame_p2p_message(b'verack', b''),
        ]
        fake = _FakeSocket(peer_messages)

        with mock.patch('socket.create_connection', return_value=fake):
            with _P2PPeerSession('fake.example', 8333) as session:
                # Reaching here means handshake succeeded
                self.assertIsNotNone(session.sock)
        # Two messages should have been sent: our version, then verack
        self.assertEqual(len(fake.sent), 2)

    def test_request_headers_returns_parsed_list(self):
        """request_headers returns the headers from a canned 'headers' response"""
        h0 = self._genesis_header()
        peer_messages = [
            _frame_p2p_message(b'version', bitcoin.messages.msg_version().to_bytes()[24:]),
            _frame_p2p_message(b'verack', b''),
            _frame_p2p_message(b'headers', _build_headers_message_body([h0])),
        ]
        fake = _FakeSocket(peer_messages)

        with mock.patch('socket.create_connection', return_value=fake):
            with _P2PPeerSession('fake.example', 8333) as session:
                headers = session.request_headers(b'\x00' * 32)
                self.assertEqual(len(headers), 1)
                self.assertEqual(headers[0].serialize(), h0.serialize())

    def test_request_headers_responds_to_ping(self):
        """A 'ping' arriving before 'headers' is answered with 'pong'"""
        import struct
        h0 = self._genesis_header()
        ping_body = struct.pack(b'<Q', 0x1234567890abcdef)
        peer_messages = [
            _frame_p2p_message(b'version', bitcoin.messages.msg_version().to_bytes()[24:]),
            _frame_p2p_message(b'verack', b''),
            _frame_p2p_message(b'ping', ping_body),
            _frame_p2p_message(b'headers', _build_headers_message_body([h0])),
        ]
        fake = _FakeSocket(peer_messages)

        with mock.patch('socket.create_connection', return_value=fake):
            with _P2PPeerSession('fake.example', 8333) as session:
                headers = session.request_headers(b'\x00' * 32)
                self.assertEqual(len(headers), 1)
        # Sent: our version, verack, getheaders, pong = 4 messages
        self.assertEqual(len(fake.sent), 4)
        # Last sent should be a pong containing the same nonce
        last = fake.sent[-1]
        self.assertEqual(last[4:4 + len(b'pong')].rstrip(b'\x00'), b'pong')


class TestP2PFetcher(unittest.TestCase):

    def test_rejects_non_genesis_archive(self):
        """P2P fetcher refuses archives that don't start at genesis"""
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, 'partial.headers.bin')
            archive = HeaderArchive(p)
            archive.create('mainnet', 800000)
            fetcher = BitcoinP2PHeaderFetcher(network='mainnet')
            with self.assertRaises(P2PFetcherError):
                fetcher.fetch_into(archive)

    def test_constructor_holds_explicit_peers(self):
        """Constructor stores explicit peers without invoking DNS"""
        peers = [('1.2.3.4', 8333), ('5.6.7.8', 8333)]
        f = BitcoinP2PHeaderFetcher(peers=peers)
        self.assertEqual(f.get_peers(), peers)


class TestLocalVerifyCacheHeaderSource(unittest.TestCase):
    """Verify cache wrapped as a BlockHeaderSource for --headers PATH."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self._tmpdir.name, 'verify-cache.bin')
        self.genesis = genesis_header()

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_returns_cached_header(self):
        c = VerifyCache(self.cache_path)
        c.create('mainnet')
        c.add(0, self.genesis)
        # A record is returned only when the user's archive agrees with it.
        src = LocalVerifyCacheHeaderSource(c, cross_check=_MockHeaderSource({0: self.genesis}))
        out = src.get_header_at_height(0)
        self.assertEqual(out.serialize(), self.genesis.serialize())

    def test_missing_height_raises_indexerror(self):
        c = VerifyCache(self.cache_path)
        c.create('mainnet')
        c.add(0, self.genesis)
        src = LocalVerifyCacheHeaderSource(c)
        with self.assertRaises(IndexError):
            src.get_header_at_height(42)

    def test_block_count_returns_highest(self):
        c = VerifyCache(self.cache_path)
        c.create('mainnet')
        c.add(0, self.genesis)
        c.add(42, self.genesis)  # PoW passes; we're just testing tip semantics
        src = LocalVerifyCacheHeaderSource(c)
        self.assertEqual(src.get_block_count(), 42)


class TestDetectArchiveFormat(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_detects_dense_archive(self):
        path = os.path.join(self._tmpdir.name, 'a.bin')
        a = HeaderArchive(path)
        a.create('mainnet', 0)
        self.assertEqual(detect_archive_format(path), ARCHIVE_MAGIC)

    def test_detects_sparse_cache(self):
        path = os.path.join(self._tmpdir.name, 'c.bin')
        c = VerifyCache(path)
        c.create('mainnet')
        self.assertEqual(detect_archive_format(path), VERIFY_CACHE_MAGIC)

    def test_unknown_magic_returned_as_is(self):
        path = os.path.join(self._tmpdir.name, 'x.bin')
        with open(path, 'wb') as fd:
            fd.write(b'JUNK' + b'\x00' * 12)
        magic = detect_archive_format(path)
        self.assertEqual(magic, b'JUNK')
        self.assertNotEqual(magic, ARCHIVE_MAGIC)
        self.assertNotEqual(magic, VERIFY_CACHE_MAGIC)


class TestBuildSidecarFromHeights(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.sidecar_path = os.path.join(self._tmpdir.name, 'side.bin')
        self.genesis = genesis_header()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _make_fetcher(self, headers_by_height, fail_for=None):
        s = _MockHeaderSource(headers_by_height, fail_for_heights=fail_for)
        return HeaderFetcher([s], quorum=1)

    def test_single_height_builds_sidecar(self):
        """One height -> sparse cache with one record."""
        fetcher = self._make_fetcher({358391: self.genesis})
        info = build_sidecar_from_heights(
            [358391], self.sidecar_path, 'mainnet', fetcher, log=False)
        self.assertEqual(info['network'], 'mainnet')
        self.assertEqual(info['header_count'], 1)
        self.assertEqual(info['heights'], [358391])
        self.assertTrue(os.path.isfile(self.sidecar_path))
        # Sidecar is valid OTSV
        self.assertEqual(detect_archive_format(self.sidecar_path),
                         VERIFY_CACHE_MAGIC)
        cache = VerifyCache(self.sidecar_path)
        net, count = cache.read_file_header()
        self.assertEqual(net, 'mainnet')
        self.assertEqual(count, 1)

    def test_multiple_heights_combined(self):
        """Multiple heights produce one sidecar with all of them, sorted."""
        fetcher = self._make_fetcher({
            358391: self.genesis,
            129405: self.genesis,
        })
        info = build_sidecar_from_heights(
            [358391, 129405], self.sidecar_path, 'mainnet',
            fetcher, log=False)
        self.assertEqual(info['header_count'], 2)
        # Heights are sorted for predictable on-disk order
        self.assertEqual(info['heights'], [129405, 358391])

    def test_duplicate_heights_deduped(self):
        """Duplicate heights in input produce just one record each."""
        fetcher = self._make_fetcher({100: self.genesis})
        info = build_sidecar_from_heights(
            [100, 100, 100], self.sidecar_path, 'mainnet',
            fetcher, log=False)
        self.assertEqual(info['header_count'], 1)
        self.assertEqual(info['heights'], [100])

    def test_empty_heights_raises(self):
        """Empty heights list is a usage error."""
        fetcher = self._make_fetcher({})
        with self.assertRaises(HeaderArchiveError) as ctx:
            build_sidecar_from_heights(
                [], self.sidecar_path, 'mainnet', fetcher, log=False)
        self.assertIn('No heights', str(ctx.exception))

    def test_refuses_overwrite_without_force(self):
        with open(self.sidecar_path, 'wb') as fd:
            fd.write(b'preexisting')
        fetcher = self._make_fetcher({100: self.genesis})
        with self.assertRaises(HeaderArchiveError) as ctx:
            build_sidecar_from_heights(
                [100], self.sidecar_path, 'mainnet', fetcher,
                force=False, log=False)
        self.assertIn('already exists', str(ctx.exception))
        with open(self.sidecar_path, 'rb') as fd:
            self.assertEqual(fd.read(), b'preexisting')

    def test_force_overwrites(self):
        with open(self.sidecar_path, 'wb') as fd:
            fd.write(b'preexisting')
        fetcher = self._make_fetcher({100: self.genesis})
        info = build_sidecar_from_heights(
            [100], self.sidecar_path, 'mainnet', fetcher,
            force=True, log=False)
        self.assertEqual(info['header_count'], 1)
        self.assertEqual(detect_archive_format(self.sidecar_path),
                         VERIFY_CACHE_MAGIC)


class _MockHTTPResponse:
    """Mimics urllib.request.urlopen's return value for tests.

    Supports the context-manager protocol and a chunked .read(n) interface.
    """

    def __init__(self, body):
        self._body = body
        self._pos = 0

    def read(self, n=None):
        if n is None or n < 0:
            chunk = self._body[self._pos:]
            self._pos = len(self._body)
            return chunk
        chunk = self._body[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestBootstrapFromUrl(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.output_path = os.path.join(self._tmpdir.name, 'headers.bin')
        self.genesis = genesis_header()

        # Build a valid 1-header mainnet archive once and reuse the bytes
        # as the "served" body for the mocked URL.
        template = os.path.join(self._tmpdir.name, '_template.bin')
        a = HeaderArchive(template)
        a.create('mainnet', 0)
        a.append_header(self.genesis)
        with open(template, 'rb') as fd:
            self.valid_archive_bytes = fd.read()
        os.unlink(template)

        # Pre-compute the SHA-256 of the valid archive for sha256 tests.
        self.valid_sha256 = hashlib.sha256(self.valid_archive_bytes).hexdigest()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _patch_urlopen(self, body):
        return mock.patch('urllib.request.urlopen',
                          return_value=_MockHTTPResponse(body))

    def test_happy_path(self):
        """Valid archive at URL is downloaded, validated, installed atomically"""
        with self._patch_urlopen(self.valid_archive_bytes):
            info = bootstrap_archive_from_url(
                'http://example.com/headers.bin',
                self.output_path, 'mainnet', log=False)

        self.assertEqual(info['network'], 'mainnet')
        self.assertEqual(info['header_count'], 1)
        self.assertEqual(info['start_height'], 0)
        self.assertEqual(info['sha256'], self.valid_sha256)
        self.assertTrue(os.path.isfile(self.output_path))
        self.assertFalse(os.path.isfile(self.output_path + '.partial'))

        # Installed file is byte-identical to served bytes.
        with open(self.output_path, 'rb') as fd:
            self.assertEqual(fd.read(), self.valid_archive_bytes)

    def test_sha256_match_passes(self):
        """Matching --sha256 succeeds"""
        with self._patch_urlopen(self.valid_archive_bytes):
            info = bootstrap_archive_from_url(
                'http://example.com/headers.bin',
                self.output_path, 'mainnet',
                expected_sha256=self.valid_sha256, log=False)
        self.assertEqual(info['sha256'], self.valid_sha256)

    def test_sha256_mismatch_raises_and_no_install(self):
        """Wrong --sha256 fails before validation, partial preserved"""
        wrong_sha = '0' * 64
        with self._patch_urlopen(self.valid_archive_bytes):
            with self.assertRaises(HeaderArchiveError) as ctx:
                bootstrap_archive_from_url(
                    'http://example.com/headers.bin',
                    self.output_path, 'mainnet',
                    expected_sha256=wrong_sha, log=False)
        self.assertIn('SHA-256 mismatch', str(ctx.exception))
        self.assertFalse(os.path.isfile(self.output_path))
        self.assertTrue(os.path.isfile(self.output_path + '.partial'))

    def test_network_mismatch_raises(self):
        """Archive built for one network rejected when caller expects another"""
        with self._patch_urlopen(self.valid_archive_bytes):
            with self.assertRaises(HeaderArchiveNetworkMismatch):
                bootstrap_archive_from_url(
                    'http://example.com/headers.bin',
                    self.output_path, 'testnet', log=False)
        self.assertFalse(os.path.isfile(self.output_path))
        self.assertTrue(os.path.isfile(self.output_path + '.partial'))

    def test_invalid_magic_raises(self):
        """Body with wrong magic is rejected"""
        bad_body = b'XXXX' + self.valid_archive_bytes[4:]
        with self._patch_urlopen(bad_body):
            with self.assertRaises(HeaderArchiveFormatError):
                bootstrap_archive_from_url(
                    'http://example.com/headers.bin',
                    self.output_path, 'mainnet', log=False)
        self.assertFalse(os.path.isfile(self.output_path))
        self.assertTrue(os.path.isfile(self.output_path + '.partial'))

    def test_pow_failure_raises_and_partial_preserved(self):
        """A header that fails PoW is detected during validation"""
        # Build an archive with a single header that fails PoW. We bypass
        # HeaderArchive.append_header (which would reject it) and write
        # the bytes directly.
        bad_template = os.path.join(self._tmpdir.name, '_bad.bin')
        a = HeaderArchive(bad_template)
        a.create('mainnet', 0)
        bad_header = bitcoin.core.CBlockHeader(
            nVersion=2,
            hashPrevBlock=b'\x00' * 32,
            hashMerkleRoot=b'\x11' * 32,
            nTime=0, nBits=0x1d00ffff, nNonce=0,
        )
        with open(bad_template, 'ab') as fd:
            fd.write(bad_header.serialize())
        with open(bad_template, 'rb') as fd:
            bad_body = fd.read()
        os.unlink(bad_template)

        with self._patch_urlopen(bad_body):
            with self.assertRaises(HeaderArchiveChainError) as ctx:
                bootstrap_archive_from_url(
                    'http://example.com/headers.bin',
                    self.output_path, 'mainnet', log=False)
        self.assertIn('proof-of-work', str(ctx.exception))
        self.assertFalse(os.path.isfile(self.output_path))
        self.assertTrue(os.path.isfile(self.output_path + '.partial'))

    def test_overwrites_existing_output_atomically(self):
        """A successful bootstrap replaces an existing output file"""
        # Pre-populate output with junk
        with open(self.output_path, 'wb') as fd:
            fd.write(b'old contents')

        with self._patch_urlopen(self.valid_archive_bytes):
            bootstrap_archive_from_url(
                'http://example.com/headers.bin',
                self.output_path, 'mainnet', log=False)

        with open(self.output_path, 'rb') as fd:
            self.assertEqual(fd.read(), self.valid_archive_bytes)
        self.assertFalse(os.path.isfile(self.output_path + '.partial'))

    def test_download_failure_preserves_partial_message(self):
        """A urllib failure surfaces a clear error mentioning the partial path"""
        def _raising_urlopen(*a, **kw):
            raise OSError("simulated network failure")

        with mock.patch('urllib.request.urlopen', side_effect=_raising_urlopen):
            with self.assertRaises(HeaderArchiveError) as ctx:
                bootstrap_archive_from_url(
                    'http://example.com/headers.bin',
                    self.output_path, 'mainnet', log=False)
        self.assertIn('Failed to download', str(ctx.exception))
        self.assertIn('partial preserved', str(ctx.exception))
        self.assertFalse(os.path.isfile(self.output_path))


class TestWalkValidateArchive(unittest.TestCase):
    """Direct tests of the bootstrap-time validation walker."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmpdir.name, 'headers.bin')

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_empty_archive_validates(self):
        """A zero-header archive is valid (just the file header)"""
        a = HeaderArchive(self.path)
        a.create('mainnet', 0)
        net, start, count = _walk_validate_archive(self.path, 'mainnet')
        self.assertEqual(net, 'mainnet')
        self.assertEqual(count, 0)

    def test_genesis_validates(self):
        """Single genesis header validates"""
        a = HeaderArchive(self.path)
        a.create('mainnet', 0)
        a.append_header(genesis_header())
        net, start, count = _walk_validate_archive(self.path, 'mainnet')
        self.assertEqual(count, 1)

    def test_network_mismatch_raises(self):
        a = HeaderArchive(self.path)
        a.create('mainnet', 0)
        with self.assertRaises(HeaderArchiveNetworkMismatch):
            _walk_validate_archive(self.path, 'testnet')


class TestReadPathProofOfWork(unittest.TestCase):
    """Headers read from a local file are PoW-checked on READ, not only on write.

    Writes a header that fails its own target directly to disk, bypassing the
    write-path validators, and reads it back -- the test shape that was missing
    when fametrano reviewed PR #164 (comment 6299632178).
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.bad = bitcoin.core.CBlockHeader(
            nVersion=2, hashPrevBlock=b'\x11' * 32, hashMerkleRoot=b'\x22' * 32,
            nTime=1420070400, nBits=0x1d00ffff, nNonce=0)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_dense_archive_rejects_bad_pow_on_read(self):
        p = os.path.join(self._tmpdir.name, 'bad.bin')
        a = HeaderArchive(p)
        a.create('mainnet', 967692)
        with open(p, 'ab') as fd:  # bypass append_header's validation
            fd.write(self.bad.serialize())
        with self.assertRaises(HeaderArchiveChainError) as ctx:
            a.get_header_at_height(967692)
        self.assertIn('proof-of-work', str(ctx.exception))

    def test_sparse_cache_rejects_bad_pow_on_read(self):
        p = os.path.join(self._tmpdir.name, 'bad-cache.bin')
        c = VerifyCache(p)
        c.create('mainnet')
        with open(p, 'ab') as fd:  # bypass VerifyCache.add's validation
            fd.write((967692).to_bytes(4, 'little') + self.bad.serialize())
        with self.assertRaises(HeaderArchiveChainError) as ctx:
            c.get(967692)
        self.assertIn('proof-of-work', str(ctx.exception))

    def test_genuine_header_still_reads(self):
        p = os.path.join(self._tmpdir.name, 'ok.bin')
        a = HeaderArchive(p)
        a.create('mainnet', 0)
        a.append_header(genesis_header())
        self.assertEqual(a.get_header_at_height(0).serialize(),
                         genesis_header().serialize())


# Real mainnet headers at heights 1 and 2 (80 bytes each), for archives
# that chain from genesis in tests.
MAINNET_BLOCK1 = bytes.fromhex(
    '010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000'
    '982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649'
    'ffff001d01e36299')
# A difficulty-1 header on top of genesis, mined for the test below (2^32
# expected hashes). Valid work, not on the chain: block 2 does not follow it.
FORGED_BLOCK1 = bytes.fromhex(
    '010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000'
    '0059ea0ded2446e1d1e0bbcecd29bb34481bb672fbde1e9a4f274288497291d33e7604'
    'd96affff001dddf92778')
MAINNET_BLOCK2 = bytes.fromhex(
    '010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000'
    'd5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649'
    'ffff001d08d2bd61')


def _raw_archive(path, network, start_height, raw_headers):
    """An archive with `raw_headers` (bytes) written straight to disk."""
    a = HeaderArchive(path)
    a.create(network, start_height)
    with open(path, 'ab') as fd:
        for raw in raw_headers:
            fd.write(raw)
    return a


class TestArchiveAnchor(unittest.TestCase):
    """A dense archive is bound to the chain when read: header 0 is the real
    genesis, the shipped checkpoint matches where the archive reaches it, and
    PoW + continuity hold between the checkpoint and the height read (or
    from genesis when the archive stops short of the checkpoint)."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.genesis = genesis_header().serialize()
        self.block1 = bitcoin.core.CBlockHeader.deserialize(MAINNET_BLOCK1)
        self.block2 = bitcoin.core.CBlockHeader.deserialize(MAINNET_BLOCK2)

    def tearDown(self):
        self._tmpdir.cleanup()

    def path(self, name):
        return os.path.join(self._tmpdir.name, name)

    def test_genesis_archive_passes(self):
        a = _raw_archive(self.path('g.bin'), 'mainnet', 0, [self.genesis])
        self.assertEqual(check_archive_anchors(a), 0)
        check_archive_anchor(a, 0)

    def test_archive_not_starting_at_zero_refused(self):
        a = _raw_archive(self.path('p.bin'), 'mainnet', 5, [self.genesis])
        with self.assertRaises(HeaderArchiveChainError) as ctx:
            LocalArchiveHeaderSource(a).get_header_at_height(5)
        self.assertIn('does not start at genesis', str(ctx.exception))

    def test_wrong_genesis_refused(self):
        bitcoin.SelectParams('testnet')
        try:
            other = genesis_header().serialize()
        finally:
            bitcoin.SelectParams('mainnet')
        a = _raw_archive(self.path('w.bin'), 'mainnet', 0, [other])
        with self.assertRaises(HeaderArchiveChainError) as ctx:
            check_archive_anchors(a)
        self.assertIn('not the mainnet genesis', str(ctx.exception))

    def test_checkpoint_match_binds_and_walks(self):
        a = _raw_archive(self.path('c.bin'), 'mainnet', 0,
                         [self.genesis, MAINNET_BLOCK1, MAINNET_BLOCK2])
        with mock.patch.dict(CHECKPOINTS, {'mainnet': (2, self.block2.GetHash())}):
            self.assertEqual(check_archive_anchors(a), 2)
            hdr = LocalArchiveHeaderSource(a).get_header_at_height(1)
        self.assertEqual(hdr.GetHash(), self.block1.GetHash())

    def test_checkpoint_mismatch_refused(self):
        a = _raw_archive(self.path('m.bin'), 'mainnet', 0,
                         [self.genesis, MAINNET_BLOCK1, MAINNET_BLOCK2])
        with mock.patch.dict(CHECKPOINTS, {'mainnet': (2, b'\x11' * 32)}):
            with self.assertRaises(HeaderArchiveChainError) as ctx:
                LocalArchiveHeaderSource(a).get_header_at_height(1)
        self.assertIn('checkpoint', str(ctx.exception))

    def test_forged_block_below_checkpoint_refused(self):
        # Real genesis, then a mined difficulty-1 header on top of it, then
        # the real block 2 as the checkpoint. The forged header has valid
        # work of its own, so only a walk that reaches the checkpoint can
        # refuse it: block 2's prev-hash is not the forged block's hash.
        forged = bitcoin.core.CBlockHeader.deserialize(FORGED_BLOCK1)
        self.assertEqual(forged.hashPrevBlock, genesis_header().GetHash())
        bitcoin.core.CheckProofOfWork(forged.GetHash(), forged.nBits)
        a = _raw_archive(self.path('f.bin'), 'mainnet', 0,
                         [self.genesis, FORGED_BLOCK1, MAINNET_BLOCK2])
        with mock.patch.dict(CHECKPOINTS, {'mainnet': (2, self.block2.GetHash())}):
            with self.assertRaises(HeaderArchiveChainError) as ctx:
                LocalArchiveHeaderSource(a).get_header_at_height(1)
        self.assertIn('continuity breaks at height 2', str(ctx.exception))

    def test_continuity_break_refused_on_read(self):
        # Block 2 placed at height 1: valid work, does not chain to genesis.
        a = _raw_archive(self.path('b.bin'), 'mainnet', 0, [self.genesis, MAINNET_BLOCK2])
        with self.assertRaises(HeaderArchiveChainError) as ctx:
            LocalArchiveHeaderSource(a).get_header_at_height(1)
        self.assertIn('continuity breaks at height 1', str(ctx.exception))

    def test_retarget_bound_above_checkpoint(self):
        # Above the checkpoint a header may be at most 4x easier per period
        # crossed; a difficulty-1 header after a modern checkpoint is far
        # outside that, a real header is inside it.
        from otsclient.headers import max_target_above_checkpoint
        modern = 0x17034a4f                      # a 2026-era mainnet nBits
        easiest = bitcoin.core.uint256_from_compact(0x1d00ffff)
        # Same period: no slack at all.
        self.assertEqual(max_target_above_checkpoint(960000, modern, 960100),
                         bitcoin.core.uint256_from_compact(modern))
        # Two period boundaries crossed: 16x.
        self.assertEqual(max_target_above_checkpoint(960000, modern, 964521),
                         bitcoin.core.uint256_from_compact(modern) << 4)
        self.assertGreater(easiest, max_target_above_checkpoint(960000, modern, 964521))

    def test_easy_header_above_checkpoint_refused_before_pow(self):
        # The bound is checked before PoW, so a header that merely declares
        # an easy target is refused by name even if it has no valid work.
        from otsclient.headers import _walk_range
        a = _raw_archive(self.path('t.bin'), 'mainnet', 0,
                         [self.genesis, MAINNET_BLOCK1, MAINNET_BLOCK2])
        modern = 0x17034a4f
        with self.assertRaises(HeaderArchiveChainError) as ctx:
            _walk_range(a, 1, 2, bound=(1, modern))
        self.assertIn('easier target', str(ctx.exception))
        self.assertIn('height 2', str(ctx.exception))

    def test_partial_archive_without_anchor_has_none(self):
        # Starts above genesis and does not reach the checkpoint: nothing
        # binds it, so it is not an archive but supplied headers.
        a = _raw_archive(self.path('p.bin'), 'mainnet', 1, [MAINNET_BLOCK1, MAINNET_BLOCK2])
        from otsclient.headers import archive_has_anchor
        self.assertFalse(archive_has_anchor(a))
        with self.assertRaises(HeaderArchiveChainError) as ctx:
            check_archive_anchors(a)
        self.assertIn('no anchor', str(ctx.exception))

    def test_partial_archive_covering_checkpoint_is_anchored_there(self):
        a = _raw_archive(self.path('pc.bin'), 'mainnet', 1, [MAINNET_BLOCK1, MAINNET_BLOCK2])
        with mock.patch.dict(CHECKPOINTS, {'mainnet': (2, self.block2.GetHash())}):
            from otsclient.headers import archive_has_anchor
            self.assertTrue(archive_has_anchor(a))
            self.assertEqual(check_archive_anchors(a), 2)
            hdr = LocalArchiveHeaderSource(a).get_header_at_height(1)
        self.assertEqual(hdr.GetHash(), self.block1.GetHash())

    def test_bootstrap_refuses_download_without_anchor(self):
        from otsclient.headers import bootstrap_archive_from_url
        src = _raw_archive(self.path('served.bin'), 'mainnet', 1, [MAINNET_BLOCK1, MAINNET_BLOCK2])
        out = self.path('installed.bin')
        with self.assertRaises(HeaderArchiveChainError) as ctx:
            bootstrap_archive_from_url('file:///' + src.path.replace('\\', '/'), out, 'mainnet', log=False)
        self.assertIn('no anchor', str(ctx.exception))
        self.assertFalse(os.path.exists(out))


class TestSidecarRule(unittest.TestCase):
    """A sparse sidecar record is verified only by equality with the user's
    archive at that height. Otherwise verify reports it as not verified."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.genesis = genesis_header()
        p = os.path.join(self._tmpdir.name, 'side.bin')
        self.cache = VerifyCache(p)
        self.cache.create('mainnet')
        self.cache.add(0, self.genesis)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_sidecar_alone_is_not_verified(self):
        with self.assertRaises(HeaderNotVerified) as ctx:
            LocalVerifyCacheHeaderSource(self.cache).get_header_at_height(0)
        self.assertEqual(ctx.exception.height, 0)
        self.assertEqual(ctx.exception.header.GetHash(), self.genesis.GetHash())

    def test_sidecar_beyond_archive_is_not_verified(self):
        src = LocalVerifyCacheHeaderSource(self.cache, cross_check=_MockHeaderSource({}))
        with self.assertRaises(HeaderNotVerified):
            src.get_header_at_height(0)

    def test_sidecar_equal_to_archive_verifies(self):
        src = LocalVerifyCacheHeaderSource(self.cache, cross_check=_MockHeaderSource({0: self.genesis}))
        self.assertEqual(src.get_header_at_height(0).GetHash(), self.genesis.GetHash())

    def test_sidecar_disagreeing_with_archive_fails_naming_height(self):
        other = bitcoin.core.CBlockHeader(
            nVersion=1, hashPrevBlock=b'\x00' * 32, hashMerkleRoot=b'\x33' * 32,
            nTime=1, nBits=0x1d00ffff, nNonce=0)
        src = LocalVerifyCacheHeaderSource(self.cache, cross_check=_MockHeaderSource({0: other}))
        with self.assertRaises(HeaderArchiveChainError) as ctx:
            src.get_header_at_height(0)
        self.assertIn('height 0', str(ctx.exception))
        self.assertIn('disagrees', str(ctx.exception))

    def test_verify_reports_not_verified_and_fails(self):
        import types
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        from opentimestamps.core.timestamp import Timestamp
        from otsclient.cmds import verify_timestamp
        t = Timestamp(self.genesis.hashMerkleRoot)
        t.attestations.add(BitcoinBlockHeaderAttestation(0))
        alone = LocalVerifyCacheHeaderSource(self.cache)
        args = types.SimpleNamespace(cache={}, use_bitcoin=True, calendar_urls=[],
                                     get_header_source=lambda: alone)
        with self.assertLogs(level='INFO') as logs:
            good = verify_timestamp(t, args)
        self.assertFalse(good)
        out = '\n'.join(logs.output)
        self.assertIn('Not verified', out)
        self.assertNotIn('Success!', out)

        checked = LocalVerifyCacheHeaderSource(self.cache, cross_check=_MockHeaderSource({0: self.genesis}))
        args.get_header_source = lambda: checked
        with self.assertLogs(level='INFO') as logs:
            good = verify_timestamp(t, args)
        self.assertTrue(good)
        self.assertRegex('\n'.join(logs.output), r"Success! Bitcoin block 0 attests existence as of .+$")


class TestHeadersDispatch(unittest.TestCase):
    """`--headers PATH` through the real argument parser: what verifies, what
    is reported as not verified, and what is refused."""

    def setUp(self):
        import types
        import otsclient.args
        self._params = bitcoin.params.NAME
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = self._tmpdir.name
        self.cache_dir = os.path.join(self.tmp, 'cache')
        os.makedirs(self.cache_dir)
        self.dummy_ots = os.path.join(self.tmp, 'dummy.ots')
        with open(self.dummy_ots, 'wb') as fd:
            fd.write(b'\x00')
        self._patch = mock.patch.object(
            otsclient.args, 'APPDIRS', types.SimpleNamespace(user_cache_dir=self.cache_dir))
        self._patch.start()
        self._args = []
        self.genesis = genesis_header()

    def tearDown(self):
        for a in self._args:
            a.timestamp_fd.close()
        self._patch.stop()
        self._tmpdir.cleanup()
        bitcoin.SelectParams(self._params)

    def source_for(self, headers_path, net_flag=None):
        import otsclient.args
        argv = ['--cache', os.path.join(self.tmp, 'ts-cache')]
        if net_flag:
            argv.append(net_flag)
        argv += ['verify', '--headers', headers_path, self.dummy_ots]
        args = otsclient.args.parse_ots_args(argv)
        self._args.append(args)
        return args.get_header_source()

    def sparse(self, name, network='mainnet'):
        p = os.path.join(self.tmp, name)
        c = VerifyCache(p)
        c.create(network)
        c.add(0, self.genesis)
        return p

    def test_sidecar_without_archive_is_not_verified(self):
        src = self.source_for(self.sparse('side.bin'))
        with self.assertRaises(HeaderNotVerified):
            src.get_header_at_height(0)

    def test_sidecar_equal_to_default_archive_verifies(self):
        _raw_archive(os.path.join(self.cache_dir, 'headers-mainnet.bin'), 'mainnet', 0,
                     [self.genesis.serialize()])
        src = self.source_for(self.sparse('side.bin'))
        self.assertEqual(src.get_header_at_height(0).GetHash(), self.genesis.GetHash())

    def test_sidecar_disagreeing_with_default_archive_fails(self):
        bitcoin.SelectParams('testnet')
        other = genesis_header().serialize()
        bitcoin.SelectParams('mainnet')
        # The archive holds a different valid-PoW header at height 0 than
        # the sidecar does. This exercises the mismatch, not the archive's
        # anchor, so the anchor check is stubbed.
        _raw_archive(os.path.join(self.cache_dir, 'headers-mainnet.bin'), 'mainnet', 0, [other])
        src = self.source_for(self.sparse('side.bin'))
        with mock.patch('otsclient.headers.check_archive_anchor'):
            with self.assertRaises(HeaderArchiveChainError) as ctx:
                src.get_header_at_height(0)
        self.assertIn('disagrees', str(ctx.exception))

    def test_dense_file_without_anchor_is_supplied_headers(self):
        p = os.path.join(self.tmp, 'partial.bin')
        _raw_archive(p, 'mainnet', 1, [MAINNET_BLOCK1])
        src = self.source_for(p)
        self.assertIsInstance(src, LocalVerifyCacheHeaderSource)
        with self.assertRaises(HeaderNotVerified):
            src.get_header_at_height(1)

    def test_regtest_archive_reads_under_regtest_params(self):
        bitcoin.SelectParams('regtest')
        g = genesis_header()
        p = os.path.join(self.tmp, 'regtest.bin')
        a = HeaderArchive(p)
        a.create('regtest', 0)
        a.append_header(g)
        bitcoin.SelectParams('mainnet')
        src = self.source_for(p, '--btc-regtest')
        self.assertEqual(src.get_header_at_height(0).GetHash(), g.GetHash())
        self.assertEqual(bitcoin.params.NAME, 'regtest')


class TestPruneVerifierStates(unittest.TestCase):
    """`prune --verify` exits 1 on a rejected or unverified header, never with a traceback."""

    def _run(self, source):
        import types
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        from opentimestamps.core.timestamp import Timestamp
        from otsclient.cmds import verify_all_attestations
        g = genesis_header()
        t = Timestamp(g.hashMerkleRoot)
        t.attestations.add(BitcoinBlockHeaderAttestation(5))
        args = types.SimpleNamespace(use_bitcoin=True, get_header_source=lambda: source)
        with self.assertLogs(level='ERROR') as logs:
            with self.assertRaises(SystemExit) as ctx:
                verify_all_attestations(t, [BitcoinBlockHeaderAttestation], args)
        self.assertEqual(ctx.exception.code, 1)
        return '\n'.join(logs.output)

    def test_rejected_header_exits(self):
        class Src(BlockHeaderSource):
            def get_header_at_height(self, height):
                raise HeaderArchiveChainError("Header at height 5 fails proof-of-work check")
        self.assertIn('proof-of-work', self._run(Src()))

    def test_unverified_header_exits(self):
        g = genesis_header()

        class Src(BlockHeaderSource):
            def get_header_at_height(self, height):
                raise HeaderNotVerified(height, g, 'side.bin')
        self.assertIn('not verified', self._run(Src()))


class TestAutoFetchBadCacheRecord(unittest.TestCase):
    """A verify-cache record that fails PoW is bypassed and fetched again."""

    def test_bad_record_is_bypassed(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, 'vc.bin')
            c = VerifyCache(p)
            c.create('mainnet')
            bad = bitcoin.core.CBlockHeader(
                nVersion=2, hashPrevBlock=b'\x11' * 32, hashMerkleRoot=b'\x22' * 32,
                nTime=1420070400, nBits=0x1d00ffff, nNonce=0)
            with open(p, 'ab') as fd:
                fd.write((967692).to_bytes(4, 'little') + bad.serialize())
            genesis = genesis_header()

            class Fetcher:
                calls = []

                def fetch_header(self, height):
                    self.calls.append(height)
                    return genesis

            f = Fetcher()
            src = AutoFetchHeaderSource(c, f, 'mainnet', log=False)
            with self.assertLogs(level='WARNING') as logs:
                hdr = src.get_header_at_height(967692)
            self.assertEqual(hdr.GetHash(), genesis.GetHash())
            self.assertEqual(f.calls, [967692])
            self.assertIn(p, '\n'.join(logs.output))


# vim:syntax=python filetype=python
