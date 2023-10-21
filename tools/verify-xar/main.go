package main

import (
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	xar "github.com/korylprince/goxar"
)

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		fmt.Println("One positional arguments is required. - archive.xar")
		flag.Usage()
		os.Exit(1)
	}

	pkgFile := args[0]

	r, err := xar.OpenReader(pkgFile)
	if err != nil {
		fmt.Printf("error opening reader err=%s\n", err.Error())
		os.Exit(1)
	}

	errors := 0
	if !r.HasSignature() {
		fmt.Printf("SignatureCreationTime=%v\n", r.SignatureCreationTime)
		errors++
	}

	if r.SignatureError != nil {
		fmt.Printf("SignatureError=%v\n", r.SignatureError)
		errors++
	}

	if errors == 0 {
		fmt.Printf("package %s DOES have a valid signature\n", pkgFile)
	}

	for _, cert := range r.Certificates {
		printCertificateInfo(cert)
	}

	for _, file := range r.File {
		if file.Type == xar.FileTypeDirectory {
			continue
		}

		fmt.Printf("reading %+#v\n", file.Name)
		rc, err := file.Open()
		if err != nil {
			fmt.Printf("error opening file err=%s\n", err.Error())
			continue
		}

		fileBytes, err := io.ReadAll(rc)
		if err != nil {
			fmt.Printf("error reading file err=%s\n", err.Error())
			continue
		}

		fmt.Printf("read %d bytes\n\n", len(fileBytes))
	}
}

func printCertificateInfo(cert *x509.Certificate) {
	fmt.Println("Certificate:")
	fmt.Printf("    Data:\n")
	fmt.Printf("        Version: %d (0x%x)\n", cert.Version, cert.Version-1)
	fmt.Printf("        Serial Number: %d (0x%x)\n", cert.SerialNumber, cert.SerialNumber)
	fmt.Printf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("        Issuer: %s\n", cert.Issuer)
	fmt.Printf("        Validity\n")
	fmt.Printf("            Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("            Not After : %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("        Subject: %s\n", cert.Subject)
	fmt.Printf("        Subject Public Key Info:\n")
	fmt.Printf("            Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm)
	fmt.Printf("                Public-Key: (%d bit)\n", cert.PublicKey.(*rsa.PublicKey).N.BitLen())
	fmt.Printf("                Exponent: %d (0x%x)\n", cert.PublicKey.(*rsa.PublicKey).E, cert.PublicKey.(*rsa.PublicKey).E)

	if len(cert.Extensions) > 0 {
		fmt.Printf("        X509v3 extensions:\n")
		for _, ext := range cert.Extensions {
			extStr := strings.ReplaceAll(ext.Id.String(), "1.3.6.1.5.5.7.1.", "id-pe-")
			fmt.Printf("            %s:\n", extStr)
		}
	}

	fmt.Printf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm)
}
