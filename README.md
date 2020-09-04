A collection of protocols which aim to future-proof systems, today.
They do this mainly by enhancing format values with self-description.
This allows interoperability, protocol agility, and helps us avoid
lock in.

The self-describing aspects of the protocols have a few stipulations:

* They MUST be **in-band** (with the value); not out-of-band (in context).
* They MUST avoid **lock-in** and promote extensibility.
* They MUST be **compact** and have a **binary-packed representation**.
* They MUST have a **human-readable representation**.

Unsigned-varint
---------------

VARiable INTeger format used in all the multiformats. The encoding is:

* Unsigned integers are serialized 7 bits at a time, starting with the
  least significant bits.
* The most significant bit (msb) in each output byte indicates if there
  is a continuation byte (msb = 1).
* There are no signed integers.
* Integers are minimally encoded.

Refer [unsigned-varint spec][unsigned-varint] for details.

Multibase
---------

Base encoding is converting binary-data to plain-text. There are several
base-encoding definitions that can convert binary-data to a small
subset of, typically, ASCII code. Purpose,

* Printable character set.
* A bridge to back-compatibility.
* When a channel cannot, do-not, allow binary data.

Refer [https://github.com/multiformats/multibase] for details. And there
is a rust implementation [rust-multibase][rust-multibase].

Multicodec
----------

Multicodec is an agreed-upon codec table. It is designed for use in
binary representations, such as keys or identifiers (i.e [CID][CID]).
Find the canonical table of multicodecs at [table.csv].

Refer [multicodec spec][multicodec] for details.


**Reference**:

List of all active references to multiformat specification.

* Micro-site, http://multiformats.io
* Unsigned varint, https://github.com/multiformats/unsigned-varint
* Multicodec, https://github.com/multiformats/multicodec


[unsigned-varint]: https://github.com/multiformats/unsigned-varint
[rust-multibase]: https://github.com/multiformats/rust-multibase
[multicodec]: https://github.com/multiformats/multicodec
[CID]: https://github.com/ipld/cid
[multicodec-table]: https://github.com/multiformats/multicodec/blob/master/table.csv
