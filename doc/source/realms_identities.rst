Realms, Identities, and Tokens
==============================

This chapter describes intrinsic concepts of Neuropil’s trust graph. Instead of
mandating a one-size-fits-all solution, Neuropil provides you with basic
building blocks that can be used to implement a variety of different trust
models. These building blocks are used by applications built on top of
Neuropil, as well as internally to implement the messaging layer.

Token
*****

A *token*, sometimes specifically referred to as an *aaatoken*, is a record
that represents the nodes of a directed dependency graph. It consists of a
number of predefined fields with conventional usage semantics, and can be
extended with a set of arbitrary, user-defined fields.

A token can be unambiguously referred to by its *token hash*, which is derived
from all of its contents. Referencing the hash of another token in one of its
field values creates an unambiguous directed edge from one token node to
another.

XXX - embed diagram token.svg

- See :ref:`np_aaatoken_t` for the aaatoken structure definition
- See :ref:`np_tree_t` for the structure that holds the extension fields of a
  token

Identity
********

An *identity* is a globally unique entity which is denoted by a public key, to
which the identity holds the paired private key. It is represented as a
:ref:`token`, and as such can be tied to meta-data such as references to issuer
identity and :ref:`realm` as well as restrictions on the duration of validity.

Signing the token hash of an identity and the token hash of the signing
identity with the private key of a the signing identity creates a
cryptographically verifiable, directed edge and establishes a trust dependency.
Via this mechanism, arbitrary (non-)hierarchies of trust can be implemented.
Effectively, any identity can have arbitrary quantities of super- and
sub-identities. Consequently, an identity can *own* (i.e. be the
super-identity) of any number of :ref:`node` identities.

Realm
*****

A *realm* is the set of identities(?) that contain the same identifier string
in the realm field of their token. (XXX)



