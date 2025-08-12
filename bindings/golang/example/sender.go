//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
package main

/*
This example program demonstrates how the neuropil golang language binding can be used to send end-to-end encrypted messages.
It will create a new application context, and listen on a passive port. It will also try to connect to a bootstrap node in the internet for connectivity
*/
import (
	"encoding/hex"
	"fmt"
	"os"
	"unsafe"

	"neuropil.org/neuropil"
)

// define authentication callback
func Authenticate(ac unsafe.Pointer, token neuropil.Token) bool {
	fmt.Println("authenticate: %s %s %s", token.Subject, token.Uuid, token.PublicKey)
	return true
}
// define authorization callback
func Authorize(ac unsafe.Pointer, token neuropil.Token) bool {
	fmt.Println("authorize: %s %s %s", token.Subject, token.Uuid, token.PublicKey)
	return true
}

// main loop
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

	// listen in passive mode only (stay behind firewall)
	if neuropil.Ok != neuropil.Listen(ac, "pas4", "localhost", 31415) {
		os.Exit(1)
	}
	fmt.Println("current status: ", neuropil.Status(ac))

	// extract node fingerprint
	node_fp := new(neuropil.NPId)
	neuropil.NodeFingerprint(ac, node_fp)
	fmt.Println("node fingerprint is: ", hex.EncodeToString((*node_fp)[:]))

	// set authentication callback to control connectivity
	neuropil.SetAuthenticateCB(ac, Authenticate)
	if neuropil.Ok != neuropil.Run(ac, 0.0) {
		os.Exit(1)
	}
	fmt.Println("current status: ", neuropil.Status(ac))

	// set authorization callback to control data channel
	neuropil.SetAuthorizeCB(ac, Authorize)

	// join a common bootstrap node
	if neuropil.Ok != neuropil.Join(ac, "*:udp4:demo.neuropil.io:3400") {
		os.Exit(1)
	}
	fmt.Println("current status: ", neuropil.Status(ac))

	// run the loop once
	if neuropil.Ok != neuropil.Run(ac, 0.0) {
		os.Exit(1)
	}

	// setup a datachannel and modify some of its properties
	mx_s := neuropil.GetMxProperties(ac, my_subject)
	mx_s.Role = neuropil.NP_MX_PROVIDER
	mx_s.AckMode = neuropil.NP_MX_ACK_NONE
	mx_s.AudienceType = neuropil.NP_MX_AUD_VIRTUAL
	neuropil.SetMxProperties(ac, my_subject, mx_s)
	
	// disable the data channel for a while
	neuropil.MxPropertiesDisable(ac, my_subject)

	// wait until joining the network is complete
	for {
		if neuropil.HasJoined(ac) {
			fmt.Println("neuropil joined the mesh network")
			break
		}
		if neuropil.Ok != neuropil.Run(ac, 1.0) {
			os.Exit(1)
		}
	}

	// enable the data channel again
	neuropil.MxPropertiesEnable(ac, my_subject)
	
	// run for 60 seconds
	if neuropil.Ok != neuropil.Run(ac, 60.0) {
		os.Exit(1)
	}

	// define an example message
	data := "Example Message"

	// run forever
	for {
		// send a message if a receiver has connected ... 
		if neuropil.HasReceiver(ac, my_subject) {
			fmt.Println("neuropil has a receiver for subject")
			neuropil.Send(ac, my_subject, []byte(data))
		}
		// run the loop for a second
		if neuropil.Ok != neuropil.Run(ac, 0.01) {
			os.Exit(1)
		}
	}

	// destroy the neuropil node
	neuropil.Destroy(ac, true)
}
