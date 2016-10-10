import json

from bitcoin.core import lx, CBlockHeader
from urllib.request import Request, urlopen

class BlockchainPlugin:
    URL = 'https://blockchain.info/block-height/{}?format=json'

    def __init__(self, network):
        if network is not 'mainnet':
            logging.error("Only mainnet is supported by this plugin")
            raise

    def get_block_header(self, height):
        with urlopen(self.URL.format(height)) as resp:
            if resp.status != 200:
                raise Exception("Unknown response from Blockchain.info plugin: %d" % resp.status)

            content = resp.read()
            data = json.loads(content.decode("utf8"))

            block = data['blocks'][0]
            return CBlockHeader(hashMerkleRoot=lx(block['mrkl_root']), nTime=block['time'])
