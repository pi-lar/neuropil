FAQ
***


Why do you not use SSL certificates ?
-------------------------------------

When the internal project started several bugs like heartbleet were dicovered. This led to the decision to use a modern
encryption library. In addition, certificates are not easy to parse, to add user supplied data is difficult (in comparison
to the now used (JSON) token structure). And authorization on top of SSL certificates is also not easy if you do not
supply additional data.

With hindsight: It could be an option to add SSL certificates back into the library. But then again: you could also add
gpg encryption ... maybe both ?


What about project <xxx>, why did you re-invent the wheel ?
-----------------------------------------------------------

From our point of view there are some other projects doing similar things, but none like neuropil. Many projects focus
on user to user interaction only, some focus on a secure network infrastructure. None of them focus on the exchange of
data between devices, enterprise applications directly. (Some example projects who do follow a similar approach are
I2P and GNUnet)


Why can't we do a direct integration of a device with our server infrastructure ?
---------------------------------------------------------------------------------

Well, obviously you can! But you're exposing i.e. enterprise applications to the risk of public access.

Usually you are using a intermediate hop to decouple your devices and applications because of technical and
organizational aspects. This intermediate hop requires additional configuration efforts, in consequence it becomes your
bootleneck and your single point of failure and attack. Message queing was partly invented to protect againts network
failures, today we add message queuing systems as central components.

Talking about IoT and millions of devices requires a paradigm shift of architecture solutions in our point of view.
We know from the mirai botnet (only around 400.000 devices) that single point of attacks are a bad idea, but still
platforms are set up that are "easy" to attack. Just consider that a DoS attack against a central infrastructure
component can block your complete enterprise for days !

At the same time you would like to connect devices of different vendors directly with each other. But today each vendor
only establishes connections to his own "cloud" platform. Essentially this means that IoT has become IoP (Internet of
Platforms) today, with increased integration efforts to get data out of these platforms later on.

Please, add some more resilience interoperability to your messqge queueing system !


Why is it written in (insecure) c ?
-----------------------------------

Actually to enable the use of the library on as many systems as possible (many embedded systems still require the use of
the c programming language).

But please do not despair: We are looking to implement the protocol for other programming languages as well.

C is from our point of view not "insecure", it depends how you use it. We hope that we have not used any insecure
library calls. We do run static code analysis tools to protect against errors.


I cannot start a node on my laptop, what's wrong ?
--------------------------------------------------

neuropil currently needs a valid DNS entry of your host to start up correctly. This is a consequence of the internal
routing table. It requires that all nodes are addressable by means of IP and port. The only way to check this kind of
connectivity is a dns lookup. If you switch of your network, the neuropil nodes will start (because all host names
resolve to 127.0.0.1)


This is all great, can I use it in production ?
-----------------------------------------------

please don't (for now). This is (still) an alpha release ! We are not yet using memory protection routines from sodium 
and there will be improvements to the protocol as well. But we think it is stable enough to play with it and the concepts.
