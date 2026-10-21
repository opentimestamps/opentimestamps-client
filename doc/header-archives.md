# Local header archives

Bitcoin-anchored OpenTimestamps proofs resolve to one specific Bitcoin block's merkle root. Verifying one traditionally required a local Bitcoin Core node. At 80 bytes per block the entire chain's headers fit in about 70 MB, so `ots` can verify against a local header archive instead. This page covers building, downloading and shipping archives. `README.md` has the short form.

## Building an archive

`ots headers fetch --p2p` fills an archive from genesis to the chain tip over Bitcoin's P2P `getheaders` protocol, up to 2000 headers per round trip. DNS seeds find peers by default, `--p2p-peer host[:port]` overrides:

    $ ots headers fetch --p2p
    Fetching headers via Bitcoin P2P to the chain tip
    ... fetched 5000 headers (at height 5000)
    ... fetched 10000 headers (at height 10000)
    ...
    Done. Appended 875433 header(s); archive now covers 0..875432

Re-running it against an existing archive appends from where the last fetch left off, so a periodic run keeps the archive current. The default path is `<cache_dir>/headers-<network>.bin` and `--output PATH` changes it.

Without `--p2p`, headers come one at a time from public Esplora-compatible explorers with cross-source quorum agreement, where `--until-height N` bounds the range:

    $ ots headers fetch --until-height 800000
    Created header archive .../headers-mainnet.bin (network=mainnet, start_height=0)
    Auto-detected chain tip height 875432 (from 3 source(s))
    Fetching headers 0..800000 from 3 source(s), quorum=2
    ...

Every header appended by either path is checked for proof-of-work and prev-hash continuity.

## Downloading an archive

To skip the fetch, download a prebuilt archive with `ots headers bootstrap`:

    $ ots headers bootstrap https://example.com/headers-mainnet.bin
    Downloading header archive from https://example.com/headers-mainnet.bin
    ... downloaded 10 MB
    ...
    Validating archive (PoW + chain continuity, every header)...
    Validated 949588 header(s) (heights 0..949587)
    Installed archive at .../headers-mainnet.bin

The file is validated before install: proof-of-work and continuity for every header, header 0 must be the real genesis block, and where the archive reaches the shipped checkpoint height it must hold that block. A host can give you the real chain or a rejected file. `--sha256 HEX` adds an integrity precheck, `--force` overwrites an existing archive, and `--output PATH` installs elsewhere. Sources can be anything urllib supports, including `file://`.

## How an archive is checked when verify reads it

Every header read from a local file is checked against its own proof-of-work. A dense archive is also bound to the chain. It must start at the real genesis block, or contain the shipped checkpoint block. Where it holds the checkpoint height, the block there must match. Proof-of-work and prev-hash continuity are then walked between the checkpoint and the attested height, so every header `verify` uses sits on the chain that ends at the checkpoint block. The walk costs about 10 ms per thousand headers and is cached per process. For heights near the checkpoint it takes milliseconds, and for heights near genesis it is one walk of most of the chain, a few seconds, once per process. An archive that stops short of the checkpoint is walked from genesis instead. An archive that fails any of this is refused with the reason.

The checkpoint is one `(height, hash)` per network in `otsclient/headers.py`, the same kind of per-network constant Bitcoin Core keeps as `nMinimumChainWork` and `assumevalid`, and that SPV wallets commonly ship as checkpoints. A dense file that neither starts at genesis nor contains the checkpoint (for example a window built with `--since-height`) cannot be bound to the chain. `verify` treats its headers as supplied, exactly like a sidecar.

### Why a checkpoint, and how to check it

Proof-of-work and continuity on their own do not bind an archive to the real chain. Each header is checked against the difficulty it declares, so a chain of difficulty-1 blocks from genesis passes both and costs about 2^52 hashes to make.

Bitcoin Core rules that out two ways: every header's `nBits` must equal what the retarget rule requires, and a chain is not accepted until its total work reaches `nMinimumChainWork`, a constant per network in [`src/kernel/chainparams.cpp`](https://github.com/bitcoin/bitcoin/blob/4303f3b7f0775cdbbe77faddf142e1e44fa590ca/src/kernel/chainparams.cpp#L141). Core also ships one block hash per network, [`assumevalid`](https://github.com/bitcoin/bitcoin/blob/4303f3b7f0775cdbbe77faddf142e1e44fa590ca/src/kernel/chainparams.cpp#L142), that it treats as known-good. One known block hash does most of the same job for this client with far less code, and one bound does the rest.

Below the checkpoint, a forger has no path forward, provided the walk always reaches the checkpoint. Every header's hash depends on the header before it, so changing any block below the checkpoint changes every hash above it, and the chain no longer contains the real checkpoint block. The only chain that reaches the real block at that height is the real chain. This is why the walk runs between the attested height and the checkpoint rather than up from genesis: a walk from genesis that stops at the attested height never has to connect to the checkpoint, and a forged block just above genesis would pass on its own difficulty-1 work.

Above the checkpoint, a forger could take the real chain as far as the checkpoint and append fake headers, each declaring difficulty 1 and costing about 2^32 hashes. So `verify` also applies Bitcoin's retarget bound there. Difficulty may fall by at most 4x per 2016-block period, so a header above the checkpoint may not declare a target easier than the checkpoint's times 4 for each period boundary crossed. Real headers always satisfy this. A forged header must then meet roughly the real difficulty, about 2^79 hashes each today, which is the same cost as mining the real chain. The check is a walk from the checkpoint to the attested height, not the whole chain, and no retarget calculation is reimplemented.

Archives that stop short of the checkpoint are walked from genesis, where the bound gives nothing (difficulty 1 is genuine there), so for them the 2^52 cost of a difficulty-1 chain is the residual. A short script that runs each of these attacks against a copy of your own archive, and prints what refused it and what it would cost, is at https://gist.github.com/djdarcy/facb2b42ccc561b47bbaf479b33494d7.

The constant is only as good as its provenance, so it is meant to be checked, not trusted. Any node or explorer answers in one call:

    $ bitcoin-cli getblockhash 960000
    000000000000000000001268aab06132c2dd203f77b6020462cd177942d6959d
    
    $ curl https://blockstream.info/api/block-height/960000
    $ curl https://mempool.space/api/block-height/960000

For testnet (testnet3), `bitcoin-cli -testnet getblockhash 5193919`. If the value in the source ever disagrees with your node, the source is wrong and `verify` will say so on every archive that reaches that height. That is the intended failure: a bad constant cannot and should not pass silently.

## Shipping headers with a proof

For a disclosure bundle, build a *sidecar* that covers only the block heights the proof attests to:

    $ ots headers fetch MANIFEST.sha256.asc.ots
    Building sidecar for 1 Bitcoin attestation height(s): 949414
    Fetching block 949414 header...
    Done. Wrote sidecar MANIFEST.sha256.asc.ots-btc-headers.bin
          (network=mainnet, 1 header(s) for heights 949414)

The sidecar is about 100 bytes per attested height. It sits next to the `.ots` and holds the headers the proof names. On its own it proves nothing about where those headers sit in the chain. So `ots verify --headers <sidecar>.bin <file>.ots` checks each record against the recipient's own archive at the default location. There are three outcomes:

- The record equals the archive's header at that height: the proof verifies.
- The record disagrees with the archive: verification fails, naming the block and both hashes.
- There is no archive, or the archive does not reach that height: `verify` reports the record as not verified, prints the command that would verify it, and exits 1.

A sidecar is therefore a few hundred bytes that a recipient compares to their own chain. A sender who lies is caught at the exact block. To cover several proofs with one sidecar, pass their `.ots` files together.

## Inspecting an archive

    $ ots headers info ~/.cache/opentimestamps/ots/headers-mainnet.bin
    Path:         .../headers-mainnet.bin
    Network:      mainnet
    Header count: 800001
    Height range: 0..800000
    File size:    64000016 bytes

## Verify flags

`--headers PATH` accepts a dense archive or a sparse sidecar. `--bitcoin-node URL` uses a node. The two are mutually exclusive, and each takes precedence over the default auto-fetch. Stamping is unaffected by any of this.
