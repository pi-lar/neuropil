neuropil API
************

**********
neuropil.h
**********

.. include-comment:: ../../include/neuropil.h


.. raw:: html

   <hr width=200>

*************
np_aaatoken.h
*************

.. include-comment:: ../../include/np_aaatoken.h


.. raw:: html

   <hr width=200>

****************
np_msgproperty.h
****************

.. include-comment:: ../../include/np_msgproperty.h


.. raw:: html

   <hr width=200>

*********
np_list.h
*********

.. include-comment:: ../../include/np_list.h


.. raw:: html

   <hr width=200>

*********
np_tree.h
*********

.. include-comment:: ../../include/np_tree.h


.. raw:: html

   <hr width=200>

******
tree.h
******

.. include-comment:: ../../include/tree/tree.h


.. raw:: html

   <hr width=200>


.. _neuropil_sysinfo:

************
np_sysinfo.h
************

The sysinfo subsystem can be used to exchange the current connections of a node with another one.
To activate the subsystem you may either call :c:func:`np_sysinfo_enable_slave` or :c:func:`np_sysinfo_enable_master`.
The master will then receive updates of the slave nodes and store this information locally. 

We have activated this feature in the :ref:`(App) Network support <neuropil_hydra>` as an example implementation.

.. include-comment:: ../../include/np_sysinfo.h


*********************
Module Class Overview
*********************

If you like to view the current development class overview please look into the following pdf:

https://www.lucidchart.com/publicSegments/view/0782cc3c-d0e6-43d7-86ac-27b601f28330


