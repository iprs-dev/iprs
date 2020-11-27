IPLD Foundational Principles
============================

* **Block**, A block is a chunk of an IPLD DAG, encoded in a format.
  Blocks have CIDs.
* **Node**, A node is a point in an IPLD DAG (map, list, number, etc.).
  Many nodes can exist encoded inside one Block.
* **Link**, A link is a kind of IPLD Node that points to another IPLD Node.
  Links are what make IPLD data a DAG rather than only a tree.
  Links are content-addressable (CID).
* **Path Segment**, A path segment is a piece of information that describes a
  move from one Node to a directly connected child Node. (In other words,
  a _Path-Segment_ is either a map key or a list index.)
* **Path**, A path is composed of Path Segments, thereby describing a
  traversal from one Node to another Node somewhere deeper in the DAG.
* Transforming content of a Block into Nodes conforming to the IPLD Data
  Model should never require interpretation in the context of anything
  not contained in the Block plus CID.
* Similarly, traversing an IPLD Node according to a Path should not require
  interpretation in the context of anything not already contained in that
  Node plus Path.
* **Format**, is the standardized representation of IPLD Links and Paths.
  It describes how to translate between structured data and binary.
  **MUST** remain consistent across all codec implementations.
* **Content addressability** refers to the ability to refer to content by a
  trustless identifier.
* IPLD links must not be cyclic, even if we add support for relative links.
* IPLD path resolution means the same thing, everywhere, every time.

**Reference**:

List of active multiformat specification(s).

* Micro-site, http://multiformats.io
* Unsigned varint, https://github.com/multiformats/unsigned-varint
* Multicodec, https://github.com/multiformats/multicodec

There are other implementations that can suite your need better:

* [rust implementation of multi-base][rust-multibase]

[unsigned-varint]: https://github.com/multiformats/unsigned-varint
[rust-multibase]: https://github.com/multiformats/rust-multibase
[multibase]: https://github.com/multiformats/multibase
[multicodec]: https://github.com/multiformats/multicodec
[CID]: https://github.com/ipld/cid
[multicodec-table]: https://github.com/multiformats/multicodec/blob/master/table.csv
