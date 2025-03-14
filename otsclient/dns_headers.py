# Copyright (C) The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import logging
import socket

from ipaddress import IPv6Address

from bitcoin.core import b2x, x, CBlockHeader

def get_header_from_dns(domain, n):
    domain = '%d.%d.%s' % (n, n / 10000, domain)

    logging.debug("Getting block header %d from %s" % (n, domain))

    nibble_chunks = []
    for (_family, _type, _port, _name, (addr, _, _, _)) in \
                socket.getaddrinfo(domain, None, family=socket.AF_INET6, type=socket.SocketKind.SOCK_DGRAM):

        addr = IPv6Address(addr)

        addr_bytes = addr.packed

        if addr_bytes[0:2] != b'\x20\x01':
            continue

        idx = addr_bytes[2] >> 4

        nibble_chunks.append((idx, b2x(addr_bytes[2:])[1:]))

    header_nibbles = ''
    for (_n, chunk) in sorted(nibble_chunks):
        header_nibbles += chunk

    header_bytes = x(header_nibbles)
    assert header_bytes[0] == 0

    return CBlockHeader.deserialize(header_bytes[1:])
