import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Iter "mo:base/Iter";
import H "../src";

// empty string

let b = Blob.fromArray([] : [Nat8]);

// sha256

let h1 = Blob.fromArray([227 : Nat8, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85]);
assert(H.sha256(b.vals()) == h1);

// sha224

let h2 = Blob.fromArray([209 : Nat8, 74, 2, 140, 42, 58, 43, 201, 71, 97, 2, 187, 40, 130, 52, 196, 21, 162, 176, 31, 130, 142, 166, 42, 197, 179, 228, 47]);
assert(H.sha224(b.vals()) == h2);

// string of 640,000 zero bytes

let data = Blob.fromArrayMut(Array.init<Nat8>(64, 0));
let digest = H.Digest(#sha256);
var read = 0;
for (i in Iter.range(1,10000)) {
  read += digest.write(data.vals());
};
let h3 = Blob.fromArray([61 : Nat8, 0, 237, 134, 182, 99, 205, 27, 138, 200, 43, 16, 82, 87, 205, 16, 148, 18, 249, 45, 202, 68, 32, 72, 83, 36, 57, 249, 32, 167, 246, 69]);
assert(digest.sum() == h3);
assert(read == 10000 * 64);

