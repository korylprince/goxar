// Copyright (c) 2011 Mikkel Krautz <mikkel@krautz.dk>
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package xar

import "encoding/xml"

// This file implements the logic that translates a XAR TOC
// to the internal format of this library.

type xmlXar struct {
	XMLName xml.Name `xml:"xar"`
	Toc     xmlToc
}

type xmlChecksum struct {
	XMLName xml.Name `xml:"checksum"`
	Style   string   `xml:"style,attr"`
	Offset  int64    `xml:"offset"`
	Size    int64    `xml:"size"`
}

type xmlSignature struct {
	XMLName      xml.Name `xml:"signature"`
	Style        string   `xml:"style,attr"`
	Offset       int64    `xml:"offset"`
	Size         int64    `xml:"size"`
	Certificates []string `xml:"KeyInfo>X509Data>X509Certificate"`
}

// x-signature is used by Apple as an alternative to signature
type xXMLSignature struct {
	XMLName      xml.Name `xml:"x-signature"`
	Style        string   `xml:"style,attr"`
	Offset       int64    `xml:"offset"`
	Size         int64    `xml:"size"`
	Certificates []string `xml:"KeyInfo>X509Data>X509Certificate"`
}

type xmlToc struct {
	XMLName               xml.Name `xml:"toc"`
	CreationTime          string   `xml:"creation-time"`
	Checksum              *xmlChecksum
	SignatureCreationTime float64 `xml:"signature-creation-time"`
	Signature             *xmlSignature
	XSignature            *xXMLSignature
	File                  []*xmlFile `xml:"file"`
}

type xmlFileChecksum struct {
	XMLName xml.Name
	Style   string `xml:"style,attr"`
	Digest  string `xml:",chardata"`
}

type xmlFinderCreateTime struct {
	XMLName     xml.Name `xml:"FinderCreateTime"`
	Nanoseconds int64    `xml:"nanoseconds"`
	Time        string   `xml:"time"`
}

type xmlFileEncoding struct {
	XMLName xml.Name `xml:"encoding"`
	Style   string   `xml:"style,attr"`
}

type xmlFileData struct {
	XMLName           xml.Name `xml:"data"`
	Length            int64    `xml:"length"`
	Offset            int64    `xml:"offset"`
	Size              int64    `xml:"size"`
	Encoding          xmlFileEncoding
	ArchivedChecksum  xmlFileChecksum `xml:"archived-checksum"`
	ExtractedChecksum xmlFileChecksum `xml:"extracted-checksum"`
}

type xmlFile struct {
	XMLName          xml.Name `xml:"file"`
	Id               string   `xml:"id,attr"`
	Ctime            string   `xml:"ctime"`
	Mtime            string   `xml:"mtime"`
	Atime            string   `xml:"atime"`
	Group            string   `xml:"group"`
	Gid              int      `xml:"gid"`
	User             string   `xml:"user"`
	Uid              int      `xml:"uid"`
	Mode             uint32   `xml:"mode"`
	DeviceNo         uint64   `xml:"deviceno"`
	Inode            uint64   `xml:"inode"`
	Type             string   `xml:"type"`
	Name             string   `xml:"name"`
	FinderCreateTime *xmlFinderCreateTime
	Data             *xmlFileData
	File             []*xmlFile `xml:"file"`
}
