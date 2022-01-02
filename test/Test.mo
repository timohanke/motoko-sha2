import Iter "mo:base/Iter";
import Nat8 "mo:base/Nat8";
import IterExt "../src";

let buf = IterExt.BlockBuffer<Nat8>(64);


    let iter1 = Iter.range(1,10);
    assert(buf.fill(Iter.map(iter1, Nat8.fromNat)) == 10);
    assert(buf.isFull() == false);
    assert(buf.get(0) == 1);
    assert(buf.get(9) == 10);
    assert(buf.toArray().size() == 10);

    let iter2 = Iter.range(1,100);
    assert(buf.fill(Iter.map(iter2, Nat8.fromNat)) == 54);
    assert(buf.isFull() == true);
    assert(buf.get(63) == 54);
    assert(buf.toArray().size() == 64);
