Apps & Tools
************

The following example programs may help you to develop your own solutions. The complete source code
can be found in our examples folder.

(App) Network support
---------------------

.. _neuropil_hydra:

:ref:`Every node started contributes to the stability of the network <node_count_and_its_impact>`,
So lets start a few nodes to increase the stability of **our** network. 

In this example application we activate our HTTP interface and our :ref:`monitoring services <neuropil_sysinfo>` to use the :ref:`visualization tool <node_view>`.
Build the source and start the executable "bin/neuropil_hydra".

You can now illustrate the network at http://view.neuropil.io.

.. NOTE:: source code of this example is available at examples/neuropil_hydra.c

.. include-comment:: ../../examples/neuropil_hydra.c
    

.. raw:: html

  <hr width=200>


(App) Echo service
------------------

- :ref:`neuropil_echo_client`
- :ref:`neuropil_echo_server`

.. _neuropil_echo_client:

------
Client
------

.. NOTE:: source code of this example is available at examples/neuropil_echo_client.c

.. include-comment:: ../../examples/neuropil_echo_client.c

You can now use our demo service at https://demo.neuropil.io or your own server (see below) to test your client.

.. _neuropil_echo_server:

------
Server
------

.. NOTE:: source code of this example is available at examples/neuropil_echo_server.c

.. include-comment:: ../../examples/neuropil_echo_server.c

.. raw:: html

  <hr width=200>


(App) Pingpong service
----------------------

.. _ping_pong:

As a next step we will now start a pingpong service to illustrate the callback functionality

.. NOTE:: source code of this example is available at examples/neuropil_pingpong.c

.. include-comment:: ../../examples/neuropil_pingpong.c

.. raw:: html

  <hr width=200>


(Tool) Visualisation
--------------------

.. _node_view:

We created a little HTML/JS app to visualise a neuropil network!
Try it out with our demo service at https://view.neuropil.io.

To visualize your own network please make sure you do have the :ref:`neuropil_sysinfo` subsystem enabled for your nodes.
See :ref:`(App) Network support <neuropil_hydra>` for an example implementation.
