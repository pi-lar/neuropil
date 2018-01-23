Realms, Identities, Tokens
==========================

This chapter describes the intrinsic building blocks provided by Neuropil.
Instead of mandating a one-size-fits-all solution Neuropil provides you with a
small set of versatile parts that can be used to implement a variety of
different trust models. These building blocks are to be used by applications
built on top of Neuropil, as well as by Neuropil internally to implement the
messaging layer itself. To master them means to find a good solution to your
domain-specific problem.

Token
*****

A *token*, sometimes specifically referred to as an *aaatoken*, is a record
that represents the nodes of a directed acyclic graph. It consists of a number
of predefined fields with conventional usage semantics, and can be extended
with a set of arbitrary, user-defined fields.

A token can be unambiguously referred to by its *fingerprint*, which is a hash
value derived from all of its contents. Referencing a fingerprint in one of the
fields of a token creates an unambiguous, directed edge from that token to
another.

.. image:: token.svg
    :alt: Token illustration

- See :ref:`np_aaatoken_t` for the aaatoken structure definition and
  predefined fields
- See :ref:`np_tree_t` for the structure that holds the extension fields of a
  token

Identity
********

An *identity* denotes a globally unique entity that controls the private part
of a key pair. It is represented as a token that contains the public part of
said key pair, along with meta data such as references to issuer and realm, as
well as restrictions on the duration of validity.

The entity that holds an identity can certify the authenticity of its own or
another identity by signing its fingerprint with its private key. The result is
a cryptographically verifiable edge of trust: if you trust the signee then you
might also trust the signed identity.

Realm
*****

When an identity references another identity as its *realm*, it is subordinated
to that identity. In this case, the former is called the *realm follower* and
the latter the *realm leader*. The realm follower is to be authenticated and
authorized by consulting with the realm leader.

Followers within the same realm only need to trust the realm leader, but not
each others individually. By rallying around a realm leader, a central entity
can extend authorization, but also revoke it, without consulting with the
followers individually.
