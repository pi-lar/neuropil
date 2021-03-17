..
  SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0

.. _realms:

Realms
======

When an identity references another identity as its *realm*, it is subordinated
to that identity. In this case, the former is called the *realm follower* and
the latter the *realm leader*. The realm follower is to be authenticated and
authorized by consulting with the realm leader.

Followers within the same realm only need to trust the realm leader, but not
each others individually. By rallying around a realm leader, a central entity
can extend authorization, but also revoke it, without consulting with the
followers individually.

XXX - TODO
