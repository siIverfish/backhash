Hobby cryptosystem in which `lineages` can encrypt data at different levels, and spawn sublineages that can only encrypt/decrypt at lower levels. 
This is enforced by having the enc/decryption keys of lower levels be hashes of higher-level encryption keys.
The sha256 hash of rung 100's encryption key would be rung 99's encryption key, and so on.
Kind of like a arbitrarily-long ladder, defined by the highest point and infinitely long.
You can go down the ladder, but never back up.

One application would be to create a system in which security clearances expire at a certain date. 
A lineage is spawned at some point in the future (e.g. next Saturday) and each day before that is one 'beneath' it on the ladder.
Each day, the encryption scheme is switched to a higher rung.
So, if Bob is given Thursday's encryption key, he can derive the encryption key for all of the days before it.
On Friday, he can no longer read new messages.

This was made because I was bored -- the actual implementation is probably insecure, given that initialization vector & time component were stripped from hashes.
