package main

import (
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	xar "github.com/korylprince/goxar"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pkcs12"
)

func main() {
	var identityPath, identityPass string
	flag.StringVar(&identityPath, "identitypath", "", "Path to the identity file")
	flag.StringVar(&identityPass, "identitypass", "", "Password for the identity file")
	flag.Parse()

	if identityPath == "" {
		fmt.Println("'identitypath' is required")
		flag.Usage()
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) != 2 {
		fmt.Println("Two positional arguments are required. - archive.xar signed-archive.xar")
		flag.Usage()
		os.Exit(1)
	}

	pkgFile := args[0]
	signedPkgFile := args[1]

	signingKey, certs, err := parseCerts(identityPath, identityPass)
	if err != nil {
		fmt.Println("error parsing certs err=%s", err.Error())
		os.Exit(1)
	}

	r, err := xar.OpenReader(pkgFile)
	if err != nil {
		fmt.Println("error opening reader err=%s", err.Error())
		os.Exit(1)
	}

	if err = r.Resign(signingKey, certs, signedPkgFile); err != nil {
		fmt.Println("error resigning package err=%s", err.Error())
		os.Exit(1)
	}
}

func parseCerts(identityPath, identityPass string) (key *rsa.PrivateKey, certs []*x509.Certificate, err error) {
	identity, err := os.ReadFile(identityPath)
	if err != nil {
		err = errors.Wrap(err, "reading identity")
		return
	}
	var singleCert *x509.Certificate
	keyS, singleCert, err := pkcs12.Decode(identity, identityPass)
	if err != nil {
		err = errors.Wrap(err, "decoding identity")
		return
	}
	key = keyS.(*rsa.PrivateKey)
	certs = []*x509.Certificate{singleCert}

	return
}
