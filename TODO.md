# OpenTimestamps Client TODO list

## m-of-n Calendar Submission

Clients should submit commitments to n remote calendars, wait for either all n
calendars to reply, or a timeout to be reached. In the event of a timeout, the
timestamp should be considered done if at least m of the n calendars replied.

Current behavior is essentially 2-of-2. Changing that to at least 2-of-3 would
be a big improvement for availability.


## Parallel Calendar Submission

Currently commitments are submitted to remote calendars sequentially; this
should be done in parallel.


## Tor Support

Need to add an option to route all remote calendar queries through your local
Tor proxy; see https://github.com/petertodd/dust-b-gone for an example
implementation.

Equally, it'd be good if remote calendars were accessible via onion addresses.


## "Sums" mode

Useful to have a special mode for sha256sum output that built a tree of the
hashes, and allowed for later extraction - not unlike Git tree mode.


## Digest stamping

Should be able to specify a digest to timestamp, rather than being limited to
timestamping files.


## Lite-Client Support

Probably best to add a way to get headers from calendar servers + other
sources, then check PoW. Also need to improve docs re: using a pruned node.
