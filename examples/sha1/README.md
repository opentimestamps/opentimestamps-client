# SHA1 Collision Example

This is an example of a [SHA1 collision](https://shattered.io/), in conjunction
with a timestamp proof. The two files `a` and `b` differ:

```
$ diff a b
Binary files a and b differ
```

...yet the same OTS proof can be used to validate either file:

```
$ ots verify -f a a_or_b.ots
Success! Bitcoin attests data existed as of Wed May 17 21:45:45 2017 EDT
$ ots verify -f b a_or_b.ots
Success! Bitcoin attests data existed as of Wed May 17 21:45:45 2017 EDT
```

This is actually fine, because [SHA1 is still good enough for
timestamping](https://petertodd.org/2017/sha1-and-opentimestamps-proofs).
