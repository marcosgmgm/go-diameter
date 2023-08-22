// Copyright 2013-2023 go-diameter authors.  All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Diameter Slg client example.
package main

import (
	"errors"
	"flag"
	"github.com/google/uuid"
	"github.com/marcosgmgm/go-diameter/v4/diam/sm/smpeer"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/marcosgmgm/go-diameter/v4/diam"
	"github.com/marcosgmgm/go-diameter/v4/diam/avp"
	"github.com/marcosgmgm/go-diameter/v4/diam/datatype"
	"github.com/marcosgmgm/go-diameter/v4/diam/dict"
	"github.com/marcosgmgm/go-diameter/v4/diam/sm"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var (
	addr        = flag.String("addr", "localhost:3868", "address in form of ip:port to connect to")
	host        = flag.String("diam_host", "client", "diameter identity host")
	realm       = flag.String("diam_realm", "go-diameter", "diameter identity realm")
	networkType = flag.String("network_type", "tcp", "protocol type tcp/sctp/tcp4/tcp6/sctp4/sctp6")
	retries     = flag.Uint("retries", 3, "Maximum number of retransmits")
	watchdog    = flag.Uint("watchdog", 5, "Diameter watchdog interval in seconds. 0 to disable watchdog.")
	vendorID    = flag.Uint("vendor", 10415, "Vendor ID")
	appID       = flag.Uint("app", 16777255, "AuthApplicationID")
)

func main() {

	flag.Parse()
	if len(*addr) == 0 {
		flag.Usage()
	}

	cfg := &sm.Settings{
		OriginHost:       datatype.DiameterIdentity(*host),
		OriginRealm:      datatype.DiameterIdentity(*realm),
		VendorID:         datatype.Unsigned32(*vendorID),
		ProductName:      "go-diameter-slg",
		OriginStateID:    datatype.Unsigned32(time.Now().Unix()),
		FirmwareRevision: 1,
		HostIPAddresses: []datatype.Address{
			datatype.Address(net.ParseIP("127.0.0.1")),
		},
	}

	// Create the state machine (it's a diam.ServeMux) and client.
	mux := sm.New(cfg)

	cli := &sm.Client{
		Dict:               dict.Default,
		Handler:            mux,
		MaxRetransmits:     *retries,
		RetransmitInterval: time.Second,
		EnableWatchdog:     *watchdog != 0,
		WatchdogInterval:   time.Duration(*watchdog) * time.Second,
		SupportedVendorID: []*diam.AVP{
			diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(*vendorID)),
		},
		VendorSpecificApplicationID: []*diam.AVP{
			diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
				AVP: []*diam.AVP{
					diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(*appID)),
					diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(*vendorID)),
				},
			}),
		},
	}

	// Set message handlers.
	done := make(chan struct{}, 1000)
	mux.Handle("PLA", handlePLA(done))
	mux.Handle("LRA", handleLRA(done))

	// Catch All
	mux.HandleIdx(diam.ALL_CMD_INDEX, handleAll())

	// Print error reports.
	go printErrors(mux.ErrorReports())

	conn, err := cli.DialNetwork(*networkType, *addr)
	if err != nil {
		log.Fatal(err)
	}
	/*err = sendPLR(conn, cfg)
	if err != nil {
		log.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		log.Fatal("Provide-Location-Request timeout")
	}*/

	err = sendLRR(conn, cfg)
	if err != nil {
		log.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		log.Fatal("Location-Report-Request")
	}
}

func sendPLR(c diam.Conn, cfg *sm.Settings) error {
	// Get this client's metadata from the connection object,
	// which is set by the state machine after the handshake.
	// It contains the peer's Origin-Host and Realm from the
	// CER/CEA handshake. We use it to populate the AVPs below.
	meta, ok := smpeer.FromContext(c.Context())
	if !ok {
		return errors.New("peer metadata unavailable")
	}
	sid := "session;" + (uuid.New()).String()
	m := diam.NewRequest(8388620, uint32(*appID), c.Dictionary()) // PLR ID
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sid))
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, cfg.OriginHost)
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, cfg.OriginRealm)
	m.NewAVP(avp.DestinationRealm, avp.Mbit, 0, meta.OriginRealm)
	m.NewAVP(avp.DestinationHost, avp.Mbit, 0, meta.OriginHost)
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(0))
	m.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(*vendorID)),
		},
	})
	m.NewAVP(avp.SLgLocationType, avp.Mbit, 10415, datatype.Enumerated(0))
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String("client-username"))
	m.NewAVP(avp.MSISDN, avp.Mbit, 10415, datatype.OctetString("5534998836856"))
	m.NewAVP(avp.LCSEPSClientName, avp.Mbit, 10415, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.LCSNameString, avp.Mbit, 10415, datatype.UTF8String("lca-client-name")),
			diam.NewAVP(avp.LCSFormatIndicator, avp.Mbit, 10415, datatype.Enumerated(0)),
		},
	})
	m.NewAVP(avp.LCSClientType, avp.Mbit, 10415, datatype.Enumerated(0))
	m.NewAVP(avp.LCSRequestorName, avp.Mbit, 10415, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.LCSRequestorIDString, avp.Mbit, 10415, datatype.UTF8String("lca-id-01")),
			diam.NewAVP(avp.LCSFormatIndicator, avp.Mbit, 10415, datatype.Enumerated(0)),
		},
	})
	m.NewAVP(avp.LCSPriority, avp.Mbit, 10415, datatype.Unsigned32(0))

	log.Printf("Sending PLR to %s\n%s", c.RemoteAddr(), m)
	_, err := m.WriteTo(c)
	return err
}

func sendLRR(c diam.Conn, cfg *sm.Settings) error {
	// Get this client's metadata from the connection object,
	// which is set by the state machine after the handshake.
	// It contains the peer's Origin-Host and Realm from the
	// CER/CEA handshake. We use it to populate the AVPs below.
	meta, ok := smpeer.FromContext(c.Context())
	if !ok {
		return errors.New("peer metadata unavailable")
	}
	sid := "session;" + (uuid.New()).String()
	m := diam.NewRequest(8388621, uint32(*appID), c.Dictionary()) // PLR ID
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sid))
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, cfg.OriginHost)
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, cfg.OriginRealm)
	m.NewAVP(avp.DestinationRealm, avp.Mbit, 0, meta.OriginRealm)
	m.NewAVP(avp.DestinationHost, avp.Mbit, 0, meta.OriginHost)
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(0))

	m.NewAVP(avp.LocationEvent, avp.Mbit, 10415, datatype.Enumerated(0))
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String("client-username"))
	m.NewAVP(avp.MSISDN, avp.Mbit, 10415, datatype.OctetString("5534998836856"))
	m.NewAVP(avp.IMEI, avp.Mbit, 10415, datatype.UTF8String("356133312135709"))
	m.NewAVP(avp.LocationEstimate, avp.Mbit, 10415, datatype.OctetString("0.1231,0.1234"))
	m.NewAVP(avp.AgeOfLocationEstimate, avp.Mbit, 10415, datatype.Unsigned32(0))
	m.NewAVP(avp.ECGI, avp.Mbit, 10415, datatype.OctetString("ecgi-name"))
	m.NewAVP(avp.ServingNode, avp.Mbit, 10415, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.SGSNNumber, avp.Mbit, 10415, datatype.UTF8String("5503490000002")),
			diam.NewAVP(avp.MMEName, avp.Mbit, 10415, datatype.DiameterIdentity("mme.org.br")),
			diam.NewAVP(avp.MMERealm, avp.Mbit, 10415, datatype.DiameterIdentity("realm.mme.org.br")),
			diam.NewAVP(avp.SGSNName, avp.Mbit, 10415, datatype.DiameterIdentity("sgsn.org.br")),
			diam.NewAVP(avp.SGSNRealm, avp.Mbit, 10415, datatype.DiameterIdentity("realm.sgsn.org.br")),
			diam.NewAVP(avp.MSCNumber, avp.Mbit, 10415, datatype.DiameterIdentity("55034000012345")),
			diam.NewAVP(avp.LCSCapabilitiesSets, avp.Mbit, 10415, datatype.Unsigned32(0)),
		},
	})

	log.Printf("Sending LRR to %s\n%s", c.RemoteAddr(), m)
	_, err := m.WriteTo(c)
	return err
}

func handlePLA(done chan struct{}) diam.HandlerFunc {
	ok := struct{}{}
	return func(c diam.Conn, m *diam.Message) {
		log.Printf("Received PLA to %s\n%s", c.RemoteAddr(), m)
		done <- ok
	}
}

func handleLRA(done chan struct{}) diam.HandlerFunc {
	ok := struct{}{}
	return func(c diam.Conn, m *diam.Message) {
		log.Printf("Received PRA to %s\n%s", c.RemoteAddr(), m)
		done <- ok
	}
}

func printErrors(ec <-chan *diam.ErrorReport) {
	for err := range ec {
		log.Println(err)
	}
}

func handleAll() diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		log.Printf("Received Meesage From %s\n%s\n", c.RemoteAddr(), m)
	}
}
