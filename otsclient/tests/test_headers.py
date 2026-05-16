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
    _P2PPeerSession,
    _read_p2p_message,
    _parse_headers_body,
    ARCHIVE_MAGIC,
    ARCHIVE_FILE_HEADER_SIZE,
    BLOCK_HEADER_SIZE,
    VERIFY_CACHE_MAGIC,
    VERIFY_CACHE_FILE_HEADER_SIZE,
    VERIFY_CACHE_RECORD_SIZE,
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


# vim:syntax=python filetype=python
