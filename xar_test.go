// Copyright (c) 2011 Mikkel Krautz <mikkel@krautz.dk>
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package xar

import (
	"bytes"
	"encoding/xml"
	"io/ioutil"
	"testing"
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
