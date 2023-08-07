// Copyright 2013-2023 go-diameter authors.  All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Diameter server slg example.
//
// If you'd like to test diameter over SSL, generate SSL certificates:
//   go run $GOROOT/src/crypto/tls/generate_cert.go --host localhost
//
// And start the server with `-cert_file cert.pem -key_file key.pem`.
//
// By default this server runs in a single OS thread. If you want to
// make it run on more, set the GOMAXPROCS=n environment variable.
// See Go's FAQ for details: http://golang.org/doc/faq#Why_no_multi_CPU

package main

import (
	"flag"
	"log"
	"net/http"

	_ "net/http/pprof"

	"github.com/marcosgmgm/go-diameter/v4/diam"
	"github.com/marcosgmgm/go-diameter/v4/diam/avp"
	"github.com/marcosgmgm/go-diameter/v4/diam/datatype"
	"github.com/marcosgmgm/go-diameter/v4/diam/sm"
)

func main() {
	addr := flag.String("addr", ":3868", "address in the form of ip:port to listen on")
	ppaddr := flag.String("pprof_addr", ":9000", "address in form of ip:port for the pprof server")
	host := flag.String("diam_host", "server", "diameter identity host")
	realm := flag.String("diam_realm", "go-diameter", "diameter identity realm")
	certFile := flag.String("cert_file", "", "tls certificate file (optional)")
	keyFile := flag.String("key_file", "", "tls key file (optional)")
	silent := flag.Bool("s", false, "silent mode, useful for benchmarks")
	flag.Parse()

	// Load our custom dictionary on top of the default one, which
	// always have the Base Protocol (RFC6733) and Credit Control
	// Application (RFC4006).
	//err := dict.Default.Load(bytes.NewReader([]byte(helloDictionary)))
	//if err != nil {
	//	log.Fatal(err)
	//}

	settings := &sm.Settings{
		OriginHost:       datatype.DiameterIdentity(*host),
		OriginRealm:      datatype.DiameterIdentity(*realm),
		VendorID:         13,
		ProductName:      "go-diameter",
		FirmwareRevision: 1,
	}

	// Create the state machine (mux) and set its message handlers.
	mux := sm.New(settings)
	mux.Handle("PLR", handlePLR(*silent))
	mux.Handle("LRR", handleLRR(*silent))
	mux.HandleFunc("ALL", handleALL) // Catch all.

	// Print error reports.
	go printErrors(mux.ErrorReports())

	if len(*ppaddr) > 0 {
		go func() { log.Fatal(http.ListenAndServe(*ppaddr, nil)) }()
	}

	err := listen(*addr, *certFile, *keyFile, mux)
	if err != nil {
		log.Fatal(err)
	}
}

func listen(addr, cert, key string, handler diam.Handler) error {
	// Start listening for connections.
	if len(cert) > 0 && len(key) > 0 {
		log.Println("Starting secure diameter server on", addr)
		return diam.ListenAndServeTLS(addr, cert, key, handler, nil)
	}
	log.Println("Starting diameter server on", addr)
	return diam.ListenAndServe(addr, handler, nil)
}

func handlePLR(silent bool) diam.HandlerFunc {
	type ProvideLocationRequest struct {
		SessionID                   datatype.UTF8String       `avp:"Session-Id"`
		VendorSpecificApplicationId datatype.Grouped          `avp:"Vendor-Specific-Application-Id"`
		AuthSessionState            datatype.Enumerated       `avp:"Auth-Session-State"`
		OriginHost                  datatype.DiameterIdentity `avp:"Origin-Host"`
		OriginRealm                 datatype.DiameterIdentity `avp:"Origin-Realm"`
		DestinationRealm            datatype.DiameterIdentity `avp:"Destination-Realm"`
		DestinationHost             datatype.DiameterIdentity `avp:"Destination-Host"`
		UserName                    string                    `avp:"User-Name"`
		MSISDN                      string                    `avp:"MSISDN"`
		SLgLocationType             datatype.Enumerated       `avp:"SLg-Location-Type"`
		LCSEPSClientName            datatype.Grouped          `avp:"LCS-EPS-Client-Name"`
		LCSClientType               datatype.Enumerated       `avp:"LCS-Client-Type"`
		LCSRequestorName            datatype.Grouped          `avp:"LCS-Requestor-Name"`
		LCSPriority                 datatype.Unsigned32       `avp:"LCS-Priority"`
	}
	return func(c diam.Conn, m *diam.Message) {
		if !silent {
			log.Printf("Received PLR from %s:\n%s", c.RemoteAddr(), m)
		}
		var plr ProvideLocationRequest
		if err := m.Unmarshal(&plr); err != nil {
			log.Printf("Failed to parse message from %s: %s\n%s",
				c.RemoteAddr(), err, m)
			return
		}
		a := m.Answer(diam.Success)
		a.NewAVP(avp.SessionID, avp.Mbit, 0, plr.SessionID)
		a.NewAVP(avp.OriginHost, avp.Mbit, 0, plr.DestinationHost)
		a.NewAVP(avp.OriginRealm, avp.Mbit, 0, plr.DestinationRealm)
		a.NewAVP(avp.DestinationRealm, avp.Mbit, 0, plr.OriginRealm)
		a.NewAVP(avp.DestinationHost, avp.Mbit, 0, plr.OriginHost)
		a.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
			AVP: []*diam.AVP{
				diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)),
			},
		})
		a.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(0))
		a.NewAVP(avp.ExperimentalResult, avp.Mbit, 0, &diam.GroupedAVP{
			AVP: []*diam.AVP{
				diam.NewAVP(avp.ExperimentalResultCode, avp.Mbit, 0, datatype.Unsigned32(0)),
			},
		})
		a.NewAVP(avp.LocationEstimate, avp.Mbit, 10415, datatype.OctetString("0.1231,0.1234"))
		a.NewAVP(avp.AccuracyFulfilmentIndicator, avp.Mbit, 10415, datatype.Enumerated(0))
		a.NewAVP(avp.AgeOfLocationEstimate, avp.Mbit, 10415, datatype.Unsigned32(0))
		a.NewAVP(avp.VelocityEstimate, avp.Mbit, 10415, datatype.OctetString("12345678"))
		a.NewAVP(avp.ECGI, avp.Mbit, 10415, datatype.OctetString("ecgi-name"))

		_, err := a.WriteTo(c)
		if err != nil {
			log.Printf("Failed to write message to %s: %s\n%s\n",
				c.RemoteAddr(), err, a)
			return
		}
		if !silent {
			log.Printf("Sent RIA to %s:\n%s", c.RemoteAddr(), a)
		}
	}
}

func handleLRR(silent bool) diam.HandlerFunc {
	type LocationReportRequest struct {
		SessionID             datatype.UTF8String       `avp:"Session-Id"`
		AuthSessionState      datatype.Enumerated       `avp:"Auth-Session-State"`
		OriginHost            datatype.DiameterIdentity `avp:"Origin-Host"`
		OriginRealm           datatype.DiameterIdentity `avp:"Origin-Realm"`
		DestinationRealm      datatype.DiameterIdentity `avp:"Destination-Realm"`
		DestinationHost       datatype.DiameterIdentity `avp:"Destination-Host"`
		UserName              string                    `avp:"User-Name"`
		MSISDN                string                    `avp:"MSISDN"`
		IMEI                  string                    `avp:"IMEI"`
		LocationEvent         datatype.Enumerated       `avp:"Location-Event"`
		LocationEstimate      datatype.OctetString      `avp:"Location-Estimate"`
		AgeOfLocationEstimate datatype.Unsigned32       `avp:"Age-Of-Location-Estimate"`
		ECGI                  datatype.OctetString      `avp:"ECGI"`
		ServingNode           datatype.Grouped          `avp:"Serving-Node"`
	}
	return func(c diam.Conn, m *diam.Message) {
		if !silent {
			log.Printf("Received LRR from %s:\n%s", c.RemoteAddr(), m)
		}
		var lrr LocationReportRequest
		if err := m.Unmarshal(&lrr); err != nil {
			log.Printf("Failed to parse message from %s: %s\n%s",
				c.RemoteAddr(), err, m)
			return
		}
		a := m.Answer(diam.Success)
		a.NewAVP(avp.SessionID, avp.Mbit, 0, lrr.SessionID)
		a.NewAVP(avp.OriginHost, avp.Mbit, 0, lrr.DestinationHost)
		a.NewAVP(avp.OriginRealm, avp.Mbit, 0, lrr.DestinationRealm)
		a.NewAVP(avp.DestinationRealm, avp.Mbit, 0, lrr.OriginRealm)
		a.NewAVP(avp.DestinationHost, avp.Mbit, 0, lrr.OriginHost)
		a.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
			AVP: []*diam.AVP{
				diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)),
			},
		})
		a.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(0))
		a.NewAVP(avp.ExperimentalResult, avp.Mbit, 0, &diam.GroupedAVP{
			AVP: []*diam.AVP{
				diam.NewAVP(avp.ExperimentalResultCode, avp.Mbit, 0, datatype.Unsigned32(0)),
			},
		})

		_, err := a.WriteTo(c)
		if err != nil {
			log.Printf("Failed to write message to %s: %s\n%s\n",
				c.RemoteAddr(), err, a)
			return
		}
		if !silent {
			log.Printf("Sent RIA to %s:\n%s", c.RemoteAddr(), a)
		}
	}
}

func handleALL(c diam.Conn, m *diam.Message) {
	log.Printf("Received unexpected message from %s:\n%s", c.RemoteAddr(), m)
}

func printErrors(ec <-chan *diam.ErrorReport) {
	for err := range ec {
		log.Println(err)
	}
}
