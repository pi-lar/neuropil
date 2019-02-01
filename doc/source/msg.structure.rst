
neuropil message structure

	----------------------------------------------------------------------------------
	| header       | instructions | properties         | body         | sign()       |
	----------------------------------------------------------------------------------
	| not crypted                                                                    |
	| sign(xx)                                                                       |
    use the crypto_sign_* libsoium functions. the n2n and e2e messages include a mac
	already and do not need to be signed again
	| e2e crypted                                                     | sign(node)   |
	e2e key generation: random symmetric key data
	e2e key generation: encrypt symmetric key with pfs key exchange (discovery) messages
	and send it over with separate message tag "kex"
	payload encryption/signature: crypto_secretstream_*() / rekey if new token is used
	and / or send new key material if required
	| n2n crypted                                                     | sign(node)   |
	n2n key generation: pfs key by exchanging handshake messages (step1)
	payload encryption/signature: crypto_secretstream_*() / rekey if new token is used
	and / or send new key material if required

1) handshake message
	| header       |                 |                 | (node token) | sign(node)   |
	| not crypted                                                                    |

2) pure node2node messages (join, leave, ...)
	| header       |                 |                 | (id token)                  |
	| n2n crypted                                                     | sign(node)   |

3) pure node2node messages (ping, piggy, ...)
	| header       |                 |                 | (payload)                   |
	| n2n crypted                                                     | sign(node)   |

	note: node token from header hash value must be used to verify signature of the node

4) forward node2node messages (update, ...)
    1st hop:
	| header       |                 | sign(body, hdr) | (id token)                  |
	| n2n crypted                                                     | sign(node)   |
	2st hop:
	| header       | sign(prop,node) | sign(body, hdr) | (id token)                  |
	| n2n crypted                                                     | sign(node2)  |

note: id token contains hash value of node token, which is present in the header
node token and it's public key has been transmitted in the handshake message

5) discovery messages
	1st hop:
	| header       |                 | sign(body, hdr) | (id token)                 |
	| n2n crypted                                                     | sign(node1) |
	2nd hop:
	| header       |                 | sign(body, hdr) | (id token)                 |
	| n2n crypted                                                     | sign(node2) |

6) end2end messages
	| header       |                 |                 | (pay. chunk)               |
    a)                               | encryptd symkey |                            |
                                     | e2e crypted/hmac(prop,header)                |
    b)                                                 | sym crypted                |
                                     | e2e crypted/hmac(body,header)                |
    | n2n crypted                                                     | sign(node)  |
