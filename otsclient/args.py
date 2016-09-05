# Copyright (C) 2016 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import argparse
import bitcoin

import otsclient.cmds


def parse_args(raw_args):
    parser = argparse.ArgumentParser(description="OpenTimestamps client.")

    parser.add_argument("-q", "--quiet", action="count", default=0,
                        help="Be more quiet.")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Be more verbose. Both -v and -q may be used multiple times.")

    btc_net_group  = parser.add_mutually_exclusive_group()
    btc_net_group.add_argument('--btc-testnet', dest='btc_net', action='store_const',
                        const='testnet', default='mainnet',
                        help='Use Bitcoin testnet rather than mainnet')
    btc_net_group.add_argument('--btc-regtest', dest='btc_net', action='store_const',
                        const='regtest',
                        help='Use Bitcoin regtest rather than mainnet')
    btc_net_group.add_argument('--no-bitcoin', dest='use_bitcoin', action='store_false',
                        default=True,
                        help='Disable Bitcoin entirely')

    subparsers = parser.add_subparsers(title='Subcommands',
                                       description='All operations are done through subcommands:')

    # ----- stamp -----
    parser_stamp = subparsers.add_parser('stamp', aliases=['s'],
                                         help='Timestamp files')

    parser_stamp.add_argument('-c','--calendar', metavar='URL', dest='calendar_urls', action='append', type=str,
                              default=[],
                              help='Create timestamp with the aid of a remote calendar. May be specified multiple times.')

    parser_stamp.add_argument('-w','--btc-wallet', dest='use_btc_wallet', action='store_true',
                              help='Create timestamp locally with the local Bitcoin wallet.')

    parser_stamp.add_argument('files', metavar='FILE', type=argparse.FileType('rb'),
                              nargs='+',
                              help='Filename')

    # ----- upgrade -----
    parser_upgrade = subparsers.add_parser('upgrade', aliases=['u'],
                                            help='Upgrade remote calendar timestamps to be locally verifiable')
    parser_upgrade.add_argument('-c','--calendar', metavar='URL', dest='calendar_urls', action='append', type=str,
                                default=[],
                                help='Override calendars in timestamp')
    parser_upgrade.add_argument('files', metavar='FILE', type=argparse.FileType('rb'),
                                nargs='+',
                                help='Existing timestamp(s); moved to FILE.bak')

    # ----- verify -----
    parser_verify = subparsers.add_parser('verify', aliases=['v'],
                                          help="Verify a timestamp")

    verify_target_group = parser_verify.add_mutually_exclusive_group()
    verify_target_group.add_argument('-f', metavar='FILE', dest='target_fd', type=argparse.FileType('rb'),
                                     default=None,
                                     help='Specify target file explicitly')
    verify_target_group.add_argument('-d', metavar='DIGEST', dest='hex_digest', type=str,
                                     default=None,
                                     help='Verify a (hex-encoded) digest rather than a file')

    parser_verify.add_argument('timestamp_fd', metavar='TIMESTAMP', type=argparse.FileType('rb'),
                               help='Timestamp filename')

    # ----- info -----
    parser_info = subparsers.add_parser('info', aliases=['i'],
                                            help='Show information on a timestamp')
    parser_info.add_argument('file', metavar='FILE', type=argparse.FileType('rb'),
                                help='Filename')


    parser_stamp.set_defaults(cmd_func=otsclient.cmds.stamp_command)
    parser_upgrade.set_defaults(cmd_func=otsclient.cmds.upgrade_command)
    parser_verify.set_defaults(cmd_func=otsclient.cmds.verify_command)
    parser_info.set_defaults(cmd_func=otsclient.cmds.info_command)

    args = parser.parse_args(raw_args)
    args.parser = parser
    args.verbosity = args.verbose - args.quiet

    def setup_bitcoin():
        """Setup Bitcoin-related functionality

        Sets mainnet/testnet and returns a RPC proxy.
        """
        if args.btc_net == 'testnet':
           bitcoin.SelectParams('testnet')
        elif args.btc_net == 'regtest':
           bitcoin.SelectParams('regtest')
        elif args.btc_net == 'mainnet':
           bitcoin.SelectParams('mainnet')
        else:
            assert False

        return bitcoin.rpc.Proxy()

    args.setup_bitcoin = setup_bitcoin

    return args
