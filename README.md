# The Sha2 package

This package is intented to provide an implementation of the Sha2 family of hash functions implemented in Motoko.

The initial commit will only provide Sha256.

Other functions from the family will be added once the interface has stabilized.

The code was derived from https://github.com/enzoh/motoko-sha/. In contrast to the functions there, this code can hash type `Blob`. 
More generally, it can hash type `Iter<Nat8>`. Hence, for `data` of any of the types `Blob`, `[Nat8]` or `[var Nat8]` one can call `sha256` simply by writing `sha256(data.vals())`. 
