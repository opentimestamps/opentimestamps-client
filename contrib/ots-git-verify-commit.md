ots-git-verify-commit
=====================

Inspect and verify the OpenTimestamps attestation embedded in a GPG-signed
git commit, without configuring the `gpg.program` wrapper described in
`doc/git-integration.md`. The script extracts the timestamp from the commit
signature, upgrades it via the local OTS cache and the remote calendars, and
prints the Bitcoin block height(s), merkle root(s), and attesting calendar(s).

Prerequisites
-------------

The script imports `otsclient`, `opentimestamps`, and `python-bitcoinlib`;
install the client first, e.g.:

    $ python3 setup.py develop --user

or:

    $ pip install -e .

Usage
-----

    $ contrib/ots-git-verify-commit cd71c76
    commit:  cd71c7609421bed2a07b9642a3c02a58c9fd2cdf
    ots:     git timestamp v1.1
    status:  3 Bitcoin attestation(s), earliest block 935487

    BLOCK       MERKLE_ROOT                                                       CALENDAR
    935487      9485dbde4da835c838225db82f14e8f2555aa58470b052847de9ea2e13253479  https://bob.btc.calendar.opentimestamps.org
    935489      e2bc7a128884dfeed3c41a60e3f9e6510b4f5b283bd53349081a31a367966e16  https://alice.btc.calendar.opentimestamps.org
    935543      631cafefde5f64d963aa7d6d3a411a28e0575834a279a851ce9bdfcea30ffdb0  https://finney.calendar.eternitywall.com

Attestations are sorted earliest block first: the first row is the strongest
lower bound on when the commit existed.

Options
-------

* `--bitcoin` — additionally check each merkle root against a local bitcoind
  over RPC (full verification).
* `-C <path>` — point at another git repository.
* `--no-calendar` — work offline, using only the local OTS cache.
* `-w`, `--wait` — keep polling the calendars until a complete Bitcoin
  attestation is available.
* `-q` — minimal output (only the attestation lines and errors).
* `--json` — emit a single JSON object on stdout for scripting, e.g.:

      $ contrib/ots-git-verify-commit --json HEAD | jq '.attestations[0].block'

Exit codes
----------

* `0` — at least one Bitcoin attestation found (and verified against
  bitcoind, if `--bitcoin` was given).
* `1` — error: bad arguments, missing commit, corrupt timestamp data,
  failed bitcoind check.
* `2` — timestamp present but still pending (not yet anchored in Bitcoin).
* `3` — no OpenTimestamps data in the commit.

JSON output
-----------

The `status` field mirrors the exit codes:

* `attested` — Bitcoin attestation found (verified, if `--bitcoin`).
* `verification_failed` — attestation found but the `--bitcoin` check failed.
* `pending` — waiting on calendars; `pending_calendars` lists their URLs.
* `no_timestamp` — no OpenTimestamps data in the commit.
* `error` — anything else (bad commit, corrupt data, cache failure, ...).

On success `attestations` is an array of `{block, merkle_root, calendar}`
objects, sorted by block height; with `--bitcoin` each entry also carries
`verified` (boolean) and `detail`.

Tests
-----

Unit tests live in `otsclient/tests/test_contrib_verify_commit.py`; they load
the script via `importlib` (it has no `.py` extension) and exercise
`load_timestamp()` on synthetic commits: unsigned, signed without
OpenTimestamps data, and signed with a corrupt OpenTimestamps armor —
checking the exit-code contract described above. Run them with:

    $ pytest otsclient/tests/test_contrib_verify_commit.py

They also run as part of the full suite (`pytest`) and in CI.
