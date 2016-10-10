import bitcoin
import logging
import sys

from bitcoin.core import b2lx

class RpcPlugin:
    def __init__(self, network):
        bitcoin.SelectParams(network)

        try:
            self.proxy = bitcoin.rpc.Proxy()
        except Exception as exp:
            logging.error("Could not connect to local Bitcoin node: %s" % exp)
            sys.exit(1)

    def get_block_header(self, height):
        try:
            block_count = self.proxy.getblockcount()
            blockhash = self.proxy.getblockhash(height)
        except IndexError:
            logging.error("Bitcoin block height %d not found; %d is highest known block" % (attestation.height, block_count))
            return
        except ConnectionError as exp:
            logging.error("Could not connect to local Bitcoin node: %s" % exp)
            return

        logging.debug("Attestation block hash: %s" % b2lx(blockhash))

        return self.proxy.getblockheader(blockhash)
