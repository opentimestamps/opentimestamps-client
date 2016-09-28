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
