.. _tutorial:

********
Tutorial
********

A brief introduction and tutorial how to get you started with the neuropil messaging layer.


Sending messages
****************

This example explains how to setup a simple neuropil node that will send
periodic messages to a destination.

.. NOTE:: The source code of this example is available in
          examples/neuropil_sender.c

.. NOTE:: You can modify this example program and (re)build it with
          ``scons bin/neuropil_sender``.

.. NOTE:: You can run this example like so
          ``LD_LIBRARY_PATH=build/lib:$LD_LIBRARY_PATH bin/neuropil_sender``.
          It will create and print events to a log file in the current
          directory.

.. include-comment:: ../../examples/neuropil_sender.c


Receiving messages
******************

This example explains how to setup a simple neuropil node that will receive
messages on a subject.

.. NOTE:: The source code of this example is available in
          examples/neuropil_receiver.c

.. NOTE:: You can modify this example program and (re)build it with
          ``scons bin/neuropil_receiver``.

.. NOTE:: You can run this example like so
          ``LD_LIBRARY_PATH=build/lib:$LD_LIBRARY_PATH bin/neuropil_receiver``.
          It will create and print events to a log file in the current
          directory.

.. include-comment:: ../../examples/neuropil_receiver.c


Using identities
****************

This example shows you how you can use digital identities to achieve loadbalancing between two nodes.

.. NOTE:: The source code of this example is available in
          examples/neuropil_receiver_lb.c

.. NOTE:: You can modify this example program and (re)build it with
          ``scons bin/neuropil_receiver_lb``.

.. NOTE:: You can run this example like so
          ``LD_LIBRARY_PATH=build/lib:$LD_LIBRARY_PATH bin/neuropil_receiver_lb``.
          It will create and print events to a log file in the current
          directory.

.. include-comment:: ../../examples/neuropil_receiver_lb.c


Bootstrapping a network
***********************

This example explains how to bootstrap a neuropil network.

.. NOTE:: The source code of this example is available in
          examples/neuropil_controller.c

.. NOTE:: You can modify this example program and (re)build it with
          ``scons bin/neuropil_controller``.

.. NOTE:: You can run this example like so
          ``LD_LIBRARY_PATH=build/lib:$LD_LIBRARY_PATH bin/neuropil_controller``.
          It will create and print events to a log file in the current
          directory.

.. include-comment:: ../../examples/neuropil_controller.c
