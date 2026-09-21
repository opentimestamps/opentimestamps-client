# Copyright (C) 2018 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import socket
import threading
import time
import unittest

import socks

from otsclient.args import make_common_options_arg_parser, handle_common_options, is_loopback_address


class TestIsLoopbackAddress(unittest.TestCase):
    def test_loopback(self):
        for host in ('127.0.0.1', '127.1.2.3', '::1', 'localhost', 'LocalHost',
                     'localhost.localdomain', 'ip6-localhost', '::1%lo'):
            self.assertTrue(is_loopback_address(host), host)

    def test_not_loopback(self):
        for host in ('0.0.0.0', '192.168.1.5', '10.0.0.1', '172.16.0.1',
                     '8.8.8.8', 'fe80::1', 'alice.btc.calendar.opentimestamps.org',
                     'example.com', '', None, 42):
            self.assertFalse(is_loopback_address(host), host)


class _RecordingServer(object):
    """A TCP listener that records the connections it accepts."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(5)
        # A timeout keeps _serve() from sitting in accept() forever: closing a
        # listening socket does not wake up an already blocked accept().
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.accepted = []
        self._closed = False
        self._thread = threading.Thread(target=self._serve)
        self._thread.daemon = True
        self._thread.start()

    def _serve(self):
        while not self._closed:
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted.append(addr)
            conn.close()

    def wait_for_connections(self, n, timeout=5):
        """Block until n connections have been accepted, return how many were."""
        deadline = time.time() + timeout
        while len(self.accepted) < n and time.time() < deadline:
            time.sleep(0.01)
        return len(self.accepted)

    def close(self):
        self._closed = True
        self.sock.close()
        self._thread.join(timeout=5)


class TestSocks5Proxy(unittest.TestCase):
    def setUp(self):
        # handle_common_options() monkey patches these module globals, so put
        # them back afterwards: the rest of the test suite shares the process.
        self._orig_socket = socket.socket
        self._orig_create_connection = socket.create_connection
        self.addCleanup(self._restore_socket)

    def _restore_socket(self):
        socket.socket = self._orig_socket
        socket.create_connection = self._orig_create_connection
        socks.set_default_proxy()

    def _apply_socks5_proxy(self, proxy):
        parser = make_common_options_arg_parser()
        args = parser.parse_args(['--no-cache', '--socks5-proxy', proxy])
        handle_common_options(args, parser)

    def test_loopback_destination_bypasses_proxy(self):
        target = _RecordingServer()
        proxy = _RecordingServer()
        self.addCleanup(target.close)
        self.addCleanup(proxy.close)

        self._apply_socks5_proxy('127.0.0.1:%d' % proxy.port)

        sock = socket.create_connection(('127.0.0.1', target.port), timeout=5)
        sock.close()

        self.assertEqual(target.wait_for_connections(1), 1)
        self.assertEqual(proxy.accepted, [])

    def test_loopback_hostname_bypasses_proxy(self):
        target = _RecordingServer()
        proxy = _RecordingServer()
        self.addCleanup(target.close)
        self.addCleanup(proxy.close)

        self._apply_socks5_proxy('127.0.0.1:%d' % proxy.port)

        sock = socket.create_connection(('localhost', target.port), timeout=5)
        sock.close()

        self.assertEqual(target.wait_for_connections(1), 1)
        self.assertEqual(proxy.accepted, [])

    def test_remote_destination_uses_proxy(self):
        proxy = _RecordingServer()
        self.addCleanup(proxy.close)

        self._apply_socks5_proxy('127.0.0.1:%d' % proxy.port)

        # TEST-NET-1 is guaranteed to be unroutable, so the only connection
        # that can show up is the one to the proxy itself. The proxy hangs up
        # before the SOCKS5 negotiation completes, which is fine here.
        try:
            socket.create_connection(('192.0.2.1', 8332), timeout=5)
        except (socks.ProxyError, socket.error):
            pass

        self.assertEqual(proxy.wait_for_connections(1), 1)
