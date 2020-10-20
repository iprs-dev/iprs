Cbor: Data model serialization in Rust

.-----------------.    .------------.    .--------.
| Serialized data |<-->| Data-model |<-->| Schema |
˙-----------------˙    ˙------------˙    ˙--------˙

This writeup focus on the data-model definition in Rust language
and its (de)serialization in CBOR format.

**Data model**

enum Kind {
    Null,
    Bool(bool),
    Integer(i128),
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    Link(Cid),
    List(Vec<Kind>),
    Dict(BTreeMap<String, Kind>),
}

* `Null`, `Bool`, `Integer`, `Float`, `Bytes`, `Text`, `Link` are the scalar
   kinds.
* `List` and `Dict` are recursive kinds.
* Integer, is represeted as signed 128-bit number, and overflow/underflow are
  treated as errors.
* Float is always represented as 64-bit at the data-model layer.
* Text, is utf8 encoded string.
* Link, is Content Identification. Here `Cid` type is defined as enumeration
  over cid-versions, hence it can be considered future proof, atleast
  from the point of serialization and de-serialization.
* List, is a hetergenous collection of kinds.
* Dict, support only utf8 encoded `String` as key.

Additionally,

* Kind is a sized definition whose memory footprint is known at compile time.
* Do not implement `equality` operation due to the presence of floating-point.

**Cbor serialization**

This section is essentially going to carve out a subset of CBOR specification
that is required to have as much `completeness` and as much `fittedness`
as possible, to say it IPLD parlance.

* Major-type-0, full compatibility.
* Major-type-1, full compatibility, since we are using i128 we can still
  represent -(unsigned-64-bit-number + 1) that comes on the wire.
* Major-type-2, only length prefixed encoding supported.
* Major-type-3, only length prefixed encoding supported.
* Major-type-4, only length prefixed list.
* Major-type-5, only length prefixed map, supports only string-keys, with
  strict sorting order for map-entries.
* Major-type-6, only `tag 42` is used for IPLD links (cid).
* Major-type-7, only following simple-values are supported,
  * Null, denotes that the expected value is nullable.
  * True, False, for representing boolean kinds.
  * F32, deserialization is supported, internally converted to double-precision.
  * F64, both serialization and deserialization is supported.
  * And all other simple-value are left un-supported.

A note on recursion, recursive type naturally fit recursive encoding and
decoding implementation. But this can lead to stack overflow issue if
data-model values are recursively composed of large number of list and dict
values. Similar problem exists when deserializing incoming wire-data.
To avoid this, either we have to convert the recursive encoding and
decoding implementation into a loop, or we may have to add cap on recursion
depth.

**Open points**:

* Since string is utf8 encoded, and there is collation spec for unicode,
  we have an option of doing byte-sort or confirming to collation spec.
* Does it make sense to have a separate f32 and f64 for float-kind ?
* Looks like serialization and deserialization is not isomorphic across codec.
  even if same codec is used but implemented by different language, can
  it be isomorphic ?
