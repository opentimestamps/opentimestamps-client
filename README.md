# OpenTimestamps Client

Command-line tool to create and validate timestamp proofs with the
OpenTimestamps protocol, using the Bitcoin blockchain as a timestamp notary.
Additionally this package provides timestamping of PGP signed Git commits, and
verification of timestamps for both Git commits as a whole, and individual
files within a Git repository.


## Requirements and Installation

* Python3 >= 3.4.2
* python-bitcoinlib >= 0.6.1
* GitPython >= 2.0.8 (optional, required only for Git commit rehashing support)

Additionally while OpenTimestamps can *create* timestamps without a local
Bitcoin node, to *verify* timestamps you need a local Bitcoin Core node (a
pruned node is fine). You also need to set the `rpcuser` and `rpcpassword`
options in `~/.bitcoin/bitcoin.conf` to allow the OpenTimestamps client to
connect to your node via the RPC interface.

The two required libraries are available via PyPI, and can be installed with:

    pip3 install -r requirements.txt

Once those libraries are installed, you can run the utilities directory out of
the repository; there's no system-wide installation process yet.


## Usage

### Timestamping a File

    ./ots stamp <file>


### Verifying a Timestamp

    ./ots verify <file>.ots


### Timestamping and Verifying PGP Signed Git Commits

See `doc/git-integration.md`.
