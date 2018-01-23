Realms and Identities
=====================

Identity
********

An *identity* denotes a globally unique entity that controls the private part
of a key pair. It is represented as a token that contains the public part of
said key pair, along with meta data such as references to issuer and realm, as
well as restrictions on the duration of validity.

The entity that holds an identity can certify the authenticity of its own or
another token by signing its fingerprint with its private key. The result is
a cryptographically verifiable edge of trust: if you trust the signee then you
might also trust the signed token.

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
