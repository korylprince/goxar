// Copyright (c) 2011 Mikkel Krautz <mikkel@krautz.dk>
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package xar

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/djherbis/times"
)

func TestTOCBadDates(t *testing.T) {
	data, err := ioutil.ReadFile("baddates.toc")
	if err != nil {
		t.Fatal(err)
	}

	root := &xmlXar{}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	err = decoder.Decode(root)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range root.Toc.File {
		_, err = xmlFileToFileInfo(f)
		if err != nil {
			t.Error("failed to parse file with missing dates:", err)
		}
	}

}

func TestOpenFile(t *testing.T) {
	r, err := OpenReader("payload.xar")
	if err != nil {
		t.Fatal(err)
	}

	if r.HasSignature() {
		t.Logf("XAR archive has a signature. ValidSignature=%v\n", r.ValidSignature())
		t.Logf("Certificates = %v\n", r.Certificates)
		t.Logf("\n")
	} else {
		t.Fatalf("xar archive should have had a signature, but r.HasSignature() = %v", r.HasSignature())
	}

	// dump all files in the xar archive
	for _, xf := range r.File {
		t.Logf("name:            %v\n", xf.Name)
		t.Logf("type:            %v\n", xf.Type)
		t.Logf("info:            %v\n", xf.Info)
		t.Logf("valid checksum:  %v\n", xf.VerifyChecksum())
		t.Logf("\n")
	}
}

func TestWriteFile(t *testing.T) {
	writeFilename := "tmp-payload.xar"

	privateKey, certs, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}

	w, err := OpenWriter(writeFilename, privateKey, certs)
	if err != nil {
		t.Fatal(err)
	}

	fileToAdd := "README.markdown"
	f, err := os.Open(fileToAdd)
	if err != nil {
		t.Fatal(err)
	}

	fileInfo, err := os.Stat(fileToAdd)
	if err != nil {
		t.Fatal(err)
	}

	fileTime, err := times.Stat(fileToAdd)
	if err != nil {
		t.Fatal(err)
	}

	if err := w.AddFile(fileToAdd, fileInfo, fileTime, f, true); err != nil {
		t.Fatal(err)
	}

	if len(w.File) != 1 {
		t.Fatal(fmt.Errorf("invalid file length %d", len(w.File)))
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	for _, xf := range w.File {
		t.Logf("name:                %v\n", xf.Name)
		t.Logf("type:                %v\n", xf.Type)
		t.Logf("info:                %v\n", xf.Info)
		t.Logf("compressed checksum: %x\n", xf.CompressedChecksum.Sum)
		t.Logf("extracted checksum:  %x\n", xf.ExtractedChecksum.Sum)
		t.Logf("\n")
	}

	r, err := OpenReader(writeFilename)
	if err != nil {
		t.Fatal(err)
	}

	if r.HasSignature() {
		t.Logf("XAR archive has a signature. ValidSignature=%v\n", r.ValidSignature())
		t.Logf("Certificates = %v\n", r.Certificates)
		t.Logf("\n")
	} else {
		t.Fatalf("xar archive should have had a signature")
	}

	if !r.ValidSignature() {
		t.Logf("r Certificates = %v\n", r.Certificates)
		t.Logf("w Certificates = %v\n", w.Certificates)
		t.Logf("\n")
		t.Fatalf("xar archive should have a valid signature SignatureError=%s", r.SignatureError.Error())
	}

	// dump all files in the xar archive
	for _, xf := range r.File {
		t.Logf("name:            %v\n", xf.Name)
		t.Logf("type:            %v\n", xf.Type)
		t.Logf("info:            %v\n", xf.Info)
		t.Logf("valid checksum:  %v\n", xf.VerifyChecksum())
		t.Logf("\n")
	}

	_ = os.Remove(writeFilename)
}

func generateSelfSignedCert() (*rsa.PrivateKey, []*x509.Certificate, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My Organization"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return privKey, []*x509.Certificate{cert}, nil
}

func TestResignFile(t *testing.T) {

	origArchiveFilename := "payload.xar"
	resignedArchiveFilename := "signed-payload.xar"

	r, err := OpenReader(origArchiveFilename)
	if err != nil {
		t.Fatal(err)
	}

	// if r.HasSignature() {
	// 	t.Logf("XAR archive has a signature")
	// 	t.Logf("ValidSignature=%v\n", r.ValidSignature())
	// 	t.Logf("Certificates = %v\n", r.Certificates)
	// 	t.Logf("\n")
	// } else {
	// 	t.Fatalf("xar archive should have had a signature")
	// }

	privateKey, certs, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}

	if err = r.Resign(privateKey, certs, resignedArchiveFilename); err != nil {
		t.Fatal(err)
	}

	var signedReader *Reader
	signedReader, err = OpenReader(resignedArchiveFilename)
	if err != nil {
		t.Fatal(err)
	}

	if signedReader.HasSignature() {
		t.Logf("XAR archive has a signature")
		t.Logf("ValidSignature=%v\n", signedReader.ValidSignature())
		t.Logf("Certificates = %v\n", signedReader.Certificates)
		t.Logf("\n")
	} else {
		t.Fatalf("xar archive should have had a signature")
	}

	// if !signedReader.ValidSignature() {
	// 	t.Fatalf("xar archive should have a valid signature")
	// }

	// if len(r.File) != len(signedReader.File) {
	// 	t.Fatalf("signed xar archive should have the same number of files")
	// }

	_ = os.Remove(resignedArchiveFilename)
}

func TestAddDirectory(t *testing.T) {
	writeFilename := "tmp-payload.xar"

	dirName := "payload.pkg"

	if err := createDirAndFile(dirName); err != nil {
		t.Fatalf("error creating test content err=%s", err.Error())
	}

	if err := createDirAndFile(filepath.Join(dirName, "anotherdirectory")); err != nil {
		t.Fatalf("error creating test content subdirectory err=%s", err.Error())
	}

	privateKey, certs, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}

	w, err := OpenWriter(writeFilename, privateKey, certs)
	if err != nil {
		t.Fatal(err)
	}

	if err = w.AddDirectory(dirName, true); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := OpenReader(writeFilename)
	if err != nil {
		t.Fatal(err)
	}

	if r.HasSignature() {
		t.Logf("XAR archive has a signature. ValidSignature=%v\n", r.ValidSignature())
		t.Logf("Certificates = %v\n", r.Certificates)
		t.Logf("\n")
	} else {
		t.Fatalf("xar archive should have had a signature")
	}

	if !r.ValidSignature() {
		t.Logf("r Certificates = %v\n", r.Certificates)
		t.Logf("w Certificates = %v\n", w.Certificates)
		t.Logf("\n")
		t.Fatalf("xar archive should have a valid signature SignatureError=%s", r.SignatureError.Error())
	}

	// dump all files in the xar archive
	for _, xf := range r.File {
		t.Logf("name:            %v\n", xf.Name)
		t.Logf("type:            %v\n", xf.Type)
		t.Logf("info:            %v\n", xf.Info)
		t.Logf("valid checksum:  %v\n", xf.VerifyChecksum())
		t.Logf("\n")
	}

	_ = os.Remove(writeFilename)
	_ = os.RemoveAll(dirName)
}

func createDirAndFile(dirName string) error {
	fileName := "preinstall"
	content := "hello world"

	// Create the directory
	err := os.Mkdir(dirName, 0755)
	if err != nil {
		return err
	}

	// Create the text file with content inside the directory
	filePath := fmt.Sprintf("%s/%s", dirName, fileName)
	err = ioutil.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		return err
	}

	return nil
}
