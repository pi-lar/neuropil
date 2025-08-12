//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
package main

/*
This example program demonstrates how the neuropil golang language binding can be used to setup a relay service.
It will create a new application context, and listen on port 3333 for incoming UDP4 connections. It will also try to connect to a bootstrap node in the internet for connectivity
*/
import (
	"encoding/hex"
	"fmt"
	"os"
	"unsafe"

	"neuropil.org/neuropil"
)

// define an authentication callback when other nodes join
func Authenticate(ac unsafe.Pointer, token neuropil.Token) bool {
	fmt.Println("authenticate: %s %s %s", token.Subject, token.Uuid, token.PublicKey)
	return true
}

// our main function running the relay code
func main() {

	// generate a NPId for our email address
	my_id := new(neuropil.NPId)
	neuropil.GetId(my_id, "example.mail@example.com")
	fmt.Println("Generated id is: ", hex.EncodeToString((*my_id)[:]))

	// generate a NPSubject for our productive email address Inbox
	my_subject := new(neuropil.NPSubject)
	neuropil.GenerateSubject(my_subject, "example.mail@example.com")
	fmt.Println("Generated subject is now: ", hex.EncodeToString((*my_subject)[:]))
	neuropil.GenerateSubject(my_subject, "INBOX")
	fmt.Println("Generated subject is now: ", hex.EncodeToString((*my_subject)[:]))
	neuropil.GenerateSubject(my_subject, "environment=production")
	fmt.Println("Generated subject is now: ", hex.EncodeToString((*my_subject)[:]))

	// create default settings to alter a few
	x := neuropil.DefaultSettings()
	x.LeafsetSize = 23 // use prime numbers for leafset size
	// x.NoThreads = 5 // alter the number of threads

	// create a new application context (aka a new random node)
	ac := neuropil.NewContext(x)

	fmt.Println("current status: ", neuropil.Status(ac))

	// spin up listening on port 3333 for udp4
	if neuropil.Ok != neuropil.Listen(ac, "udp4", "localhost", 3333) {
		os.Exit(1)
	}

	fmt.Println("current status: ", neuropil.Status(ac))
	node_fp := new(neuropil.NPId)
	// extract the random node fingerprint and display it
	neuropil.NodeFingerprint(ac, node_fp)
	fmt.Println("relay fingerprint is: ", hex.EncodeToString((*node_fp)[:]))

	// set authentication callback to control connectivity
	neuropil.SetAuthenticateCB(ac, Authenticate)
	if neuropil.Ok != neuropil.Run(ac, 0.0) {
		os.Exit(1)
	}
	fmt.Println("current status: ", neuropil.Status(ac))

	// connect to another bootstrap node somewhere in the internet, will trigger the authentication callback
	if neuropil.Ok != neuropil.Join(ac, "*:udp4:demo.neuropil.io:3400") {
		os.Exit(1)
	}
	fmt.Println("current status: ", neuropil.Status(ac))
	
	// run the relay for 60s 
	if neuropil.Ok != neuropil.Run(ac, 60.0) {
		os.Exit(1)
	}
	// run the relay forever
	for {
		if neuropil.Ok != neuropil.Run(ac, 1.0) {
			os.Exit(1)
		}
	}
	// destroy the relay setup
	neuropil.Destroy(ac, true)
}
