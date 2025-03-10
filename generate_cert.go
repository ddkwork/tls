// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ddkwork/golibrary/mylog"
)

var (
	host       = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFrom  = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor   = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	isCA       = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
	rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
	ed25519Key = flag.Bool("ed25519", false, "Generate an Ed25519 key")
)

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func main() {
	flag.Parse()

	if len(*host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}

	var priv any

	switch *ecdsaCurve {
	case "":
		if *ed25519Key {
			_, priv = mylog.Check3(ed25519.GenerateKey(rand.Reader))
		} else {
			priv = mylog.Check2(rsa.GenerateKey(rand.Reader, *rsaBits))
		}
	case "P224":
		priv = mylog.Check2(ecdsa.GenerateKey(elliptic.P224(), rand.Reader))
	case "P256":
		priv = mylog.Check2(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	case "P384":
		priv = mylog.Check2(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	case "P521":
		priv = mylog.Check2(ecdsa.GenerateKey(elliptic.P521(), rand.Reader))
	default:
		log.Fatalf("Unrecognized elliptic curve: %q", *ecdsaCurve)
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	var notBefore time.Time
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore = mylog.Check2(time.Parse("Jan 2 15:04:05 2006", *validFrom))
	}

	notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber := mylog.Check2(rand.Int(rand.Reader, serialNumberLimit))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(*host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if *isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes := mylog.Check2(x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv))

	certOut := mylog.Check2(os.Create("cert.pem"))
	mylog.Check(pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	mylog.Check(certOut.Close())

	log.Print("wrote cert.pem\n")

	keyOut := mylog.Check2(os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600))

	privBytes := mylog.Check2(x509.MarshalPKCS8PrivateKey(priv))
	mylog.Check(pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}))
	mylog.Check(keyOut.Close())

	log.Print("wrote key.pem\n")
}
