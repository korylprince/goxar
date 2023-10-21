// Copyright (c) 2011 Mikkel Krautz <mikkel@krautz.dk>
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

// Package xar provides for reading and writing XAR archives.
package xar

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"

	"github.com/djherbis/times"
)

var (
	ErrBadMagic      = errors.New("xar: bad magic")
	ErrBadVersion    = errors.New("xar: bad version")
	ErrBadHeaderSize = errors.New("xar: bad header size")

	ErrNoTOCChecksum        = errors.New("xar: no TOC checksum info in TOC")
	ErrChecksumUnsupported  = errors.New("xar: unsupported checksum type")
	ErrChecksumTypeMismatch = errors.New("xar: header and toc checksum type mismatch")
	ErrChecksumMismatch     = errors.New("xar: checksum mismatch")

	ErrNoCertificates             = errors.New("xar: no certificates stored in xar")
	ErrCertificateTypeMismatch    = errors.New("xar: certificate type and public key type mismatch")
	ErrCertificateTypeUnsupported = errors.New("xar: unsupported certificate type")

	ErrFileEncodingUnsupported = errors.New("xar: unsupported file encoding")

	ErrMissingCerts = errors.New("xar: missing signing certs")
)

const xarVersion = 1
const XarHeaderMagic = 0x78617221 // 'xar!'
const xarHeaderSize = 28

type xarHeader struct {
	magic         uint32
	size          uint16
	version       uint16
	toc_len_zlib  uint64
	toc_len_plain uint64
	checksum_kind uint32
}

const (
	xarChecksumKindNone = iota
	xarChecksumKindSHA1
	xarChecksumKindMD5
)

type FileType int

const (
	FileTypeFile FileType = iota
	FileTypeDirectory
	FileTypeSymlink
	FileTypeFifo
	FileTypeCharDevice
	FileTypeBlockDevice
	FileTypeSocket
)

type FileChecksumKind int

const (
	FileChecksumKindSHA1 FileChecksumKind = iota
	FileChecksumKindMD5
)

type FileInfo struct {
	DeviceNo uint64
	Mode     uint32
	Inode    uint64
	Uid      int
	User     string
	Gid      int
	Group    string
	Atime    int64
	Mtime    int64
	Ctime    int64
}

type FileChecksum struct {
	Kind FileChecksumKind
	Sum  []byte
}

type File struct {
	Type FileType
	Info FileInfo
	Id   uint64
	Name string

	EncodingMimetype   string
	CompressedChecksum FileChecksum
	ExtractedChecksum  FileChecksum
	// The size of the archived file (the size of the file after decompressing)
	Size int64

	offset int64
	length int64
	heap   io.ReaderAt
	reader io.ReadSeekCloser
}

type ReaderAtCloser interface {
	io.ReaderAt
	io.Closer
}

type Reader struct {
	File map[uint64]*File

	Certificates          []*x509.Certificate
	SignatureCreationTime int64
	SignatureError        error

	xar        ReaderAtCloser
	size       int64
	heapOffset int64
	Toc        *xmlXar
}

// OpenReader will open the XAR file specified by name and return a Reader.
func OpenReader(name string) (*Reader, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	return NewReader(f, info.Size())
}

// NewReader returns a new reader reading from r, which is assumed to have the given size in bytes.
func NewReader(r ReaderAtCloser, size int64) (*Reader, error) {
	xr := &Reader{
		File: make(map[uint64]*File),
		xar:  r,
		size: size,
		Toc:  &xmlXar{},
	}

	hdr := make([]byte, xarHeaderSize)
	_, err := xr.xar.ReadAt(hdr, 0)
	if err != nil {
		return nil, err
	}

	xh := &xarHeader{}
	xh.magic = binary.BigEndian.Uint32(hdr[0:4])
	xh.size = binary.BigEndian.Uint16(hdr[4:6])
	xh.version = binary.BigEndian.Uint16(hdr[6:8])
	xh.toc_len_zlib = binary.BigEndian.Uint64(hdr[8:16])
	xh.toc_len_plain = binary.BigEndian.Uint64(hdr[16:24])
	xh.checksum_kind = binary.BigEndian.Uint32(hdr[24:28])

	if xh.magic != XarHeaderMagic {
		return nil, ErrBadMagic
	}

	if xh.version != xarVersion {
		return nil, ErrBadVersion
	}

	if xh.size != xarHeaderSize {
		return nil, ErrBadHeaderSize
	}

	ztoc := make([]byte, xh.toc_len_zlib)
	_, err = xr.xar.ReadAt(ztoc, xarHeaderSize)
	if err != nil {
		return nil, err
	}

	br := bytes.NewBuffer(ztoc)
	zr, err := zlib.NewReader(br)
	if err != nil {
		return nil, err
	}

	decoder := xml.NewDecoder(zr)
	decoder.Strict = false
	err = decoder.Decode(xr.Toc)
	if err != nil {
		return nil, err
	}

	xr.heapOffset = xarHeaderSize + int64(xh.toc_len_zlib)

	if xr.Toc.Toc.Checksum == nil {
		return nil, ErrNoTOCChecksum
	}

	// Check whether the XAR checksum matches
	storedsum := make([]byte, xr.Toc.Toc.Checksum.Size)
	_, err = io.ReadFull(io.NewSectionReader(xr.xar, xr.heapOffset+xr.Toc.Toc.Checksum.Offset, xr.Toc.Toc.Checksum.Size), storedsum)
	if err != nil {
		return nil, err
	}

	var hasher hash.Hash
	switch xh.checksum_kind {
	case xarChecksumKindNone:
		return nil, ErrChecksumUnsupported
	case xarChecksumKindSHA1:
		if xr.Toc.Toc.Checksum.Style != "sha1" {
			return nil, ErrChecksumTypeMismatch
		}
		hasher = sha1.New()
	case xarChecksumKindMD5:
		if xr.Toc.Toc.Checksum.Style != "md5" {
			return nil, ErrChecksumTypeMismatch
		}
		hasher = md5.New()
	default:
		return nil, ErrChecksumUnsupported
	}

	_, err = hasher.Write(ztoc)
	if err != nil {
		return nil, err
	}

	calcedsum := hasher.Sum(nil)

	if !bytes.Equal(calcedsum, storedsum) {
		return nil, ErrChecksumMismatch
	}

	// Ignore error. The method automatically sets xr.SignatureError with
	// the returned error.
	_ = xr.readAndVerifySignature(xr.Toc, xh.checksum_kind, calcedsum)

	// Add files to Reader
	for _, xmlFile := range xr.Toc.Toc.File {
		err := xr.readXmlFileTree(xmlFile, "")
		if err != nil {
			return nil, err
		}
	}

	return xr, nil
}

// Reads signature information from the xmlXar element into
// the Reader. Also attempts to verify any signatures found.
func (r *Reader) readAndVerifySignature(root *xmlXar, checksumKind uint32, checksum []byte) (err error) {
	defer func() {
		r.SignatureError = err
	}()

	// Check if there's a signature ...
	r.SignatureCreationTime = int64(root.Toc.SignatureCreationTime)
	if root.Toc.Signature != nil {
		if root.Toc.Signature.Certificates == nil || len(root.Toc.Signature.Certificates) == 0 {
			return ErrNoCertificates
		}

		signature := make([]byte, root.Toc.Signature.Size)
		_, err = r.xar.ReadAt(signature, r.heapOffset+root.Toc.Signature.Offset)
		if err != nil {
			return err
		}

		// Read certificates
		for i := 0; i < len(root.Toc.Signature.Certificates); i++ {
			cb64 := []byte(strings.Replace(root.Toc.Signature.Certificates[i], "\n", "", -1))
			cder := make([]byte, base64.StdEncoding.DecodedLen(len(cb64)))

			ndec, err := base64.StdEncoding.Decode(cder, cb64)
			if err != nil {
				return err
			}

			cert, err := x509.ParseCertificate(cder[0:ndec])
			if err != nil {
				return err
			}

			r.Certificates = append(r.Certificates, cert)
		}

		// Verify validity of chain
		for i := 1; i < len(r.Certificates); i++ {
			if err := r.Certificates[i-1].CheckSignatureFrom(r.Certificates[i]); err != nil {
				return err
			}
		}

		var sighash crypto.Hash
		switch checksumKind {
		case xarChecksumKindNone:
			return ErrChecksumUnsupported
		case xarChecksumKindSHA1:
			sighash = crypto.SHA1
		case xarChecksumKindMD5:
			sighash = crypto.MD5
		}

		if root.Toc.Signature.Style == "RSA" {
			pubkey, ok := r.Certificates[0].PublicKey.(*rsa.PublicKey)
			if !ok {
				return ErrCertificateTypeMismatch
			}
			err = rsa.VerifyPKCS1v15(pubkey, sighash, checksum, signature)
			if err != nil {
				return err
			}
		} else {
			return ErrCertificateTypeUnsupported
		}
	}

	return nil
}

// Close closes the opened XAR file.
func (r *Reader) Close() error {
	return r.xar.Close()
}

// This is a convenience method that returns true if the opened XAR archive
// has a signature. Internally, it checks whether the SignatureCreationTime
// field of the Reader is > 0.
func (r *Reader) HasSignature() bool {
	return r.SignatureCreationTime > 0
}

// This is a convenience method that returns true of the signature if the
// opened XAR archive was successfully verified.
//
// For a signature to be valid, it must have been signed by the leaf certificate
// in the certificate chain of the archive.
//
// If there is more than one certificate in the chain, each certificate must come
// before the one that has issued it. This is verified by checking whether the
// signature of each certificate can be verified against the public key of the
// certificate following it.
//
// The Reader does not do anything to check whether the leaf certificate and/or
// any intermediate certificates are trusted. It is up to users of this package
// to determine whether they wish to trust a given certificate chain.
// If an archive has a signature, the certificate chain of the archive can be
// accessed through the Certificates field of the Reader.
//
// Internally, this method checks whether the SignatureError field is non-nil,
// and whether the SignatureCreationTime is > 0.
//
// If the signature is not valid, and the XAR file has a signature, the
// SignatureError field of the Reader can be used to determine a possible
// cause.
func (r *Reader) ValidSignature() bool {
	return r.SignatureCreationTime > 0 && r.SignatureError == nil
}

func (r *Reader) Resign(privateKey *rsa.PrivateKey, certificates []*x509.Certificate, resignedArchiveFilename string) (err error) {
	var w *Writer
	w, err = OpenWriter(resignedArchiveFilename, privateKey, certificates)
	if err != nil {
		return
	}

	if w.SigningKey == nil || len(w.Certificates) < 1 {
		err = ErrMissingCerts
		return
	}

	w.Toc = r.Toc
	w.Toc.Toc.SignatureCreationTime = float64(time.Now().Unix())
	w.Toc.Toc.Signature = &xmlSignature{
		Style:        "RSA",
		Offset:       20,
		Size:         256,
		Certificates: make([]string, len(w.Certificates)),
	}

	for i, c := range w.Certificates {
		w.Toc.Toc.Signature.Certificates[i] = certToBase64PEM(c)
	}

	w.heapOffset, err = writeHeaderAndToc(w.xar, w.Toc, w.SigningKey, w.File)
	if err != nil {
		return
	}

	_, err = io.Copy(w.xar, r.newHeapReader())
	if err != nil {
		return
	}

	err = w.Close()

	return
}

func xmlFileToFileInfo(xmlFile *xmlFile) (fi FileInfo, err error) {
	var t time.Time
	if xmlFile.Ctime != "" {
		t, err = time.Parse(time.RFC3339, xmlFile.Ctime)
		if err != nil {
			return
		}
		fi.Ctime = t.Unix()
	}

	if xmlFile.Mtime != "" {
		t, err = time.Parse(time.RFC3339, xmlFile.Mtime)
		if err != nil {
			return
		}
		fi.Mtime = t.Unix()
	}

	if xmlFile.Atime != "" {
		t, err = time.Parse(time.RFC3339, xmlFile.Atime)
		if err != nil {
			return
		}
		fi.Atime = t.Unix()
	}

	fi.Group = xmlFile.Group
	fi.Gid = xmlFile.Gid

	fi.User = xmlFile.User
	fi.Uid = xmlFile.Uid

	fi.Mode = xmlFile.Mode

	fi.Inode = xmlFile.Inode
	fi.DeviceNo = xmlFile.DeviceNo

	return
}

// Convert a xmlFileChecksum to a FileChecksum.
func fileChecksumFromXml(f *FileChecksum, x *xmlFileChecksum) (err error) {
	f.Sum, err = hex.DecodeString(x.Digest)
	if err != nil {
		return
	}

	switch strings.ToUpper(x.Style) {
	case "MD5":
		f.Kind = FileChecksumKindMD5
	case "SHA1", "sha1":
		f.Kind = FileChecksumKindSHA1
	default:
		return ErrChecksumUnsupported
	}

	return nil
}

// Create a new SectionReader that is limited to reading from the file's heap
func (r *Reader) newHeapReader() *io.SectionReader {
	return io.NewSectionReader(r.xar, r.heapOffset, r.size-r.heapOffset)
}

// Reads the file tree from a parse XAR TOC into the Reader.
func (r *Reader) readXmlFileTree(xmlFile *xmlFile, dir string) (err error) {
	xf := &File{}
	xf.heap = r.newHeapReader()

	if xmlFile.Type == "file" {
		xf.Type = FileTypeFile
	} else if xmlFile.Type == "directory" {
		xf.Type = FileTypeDirectory
	} else {
		return
	}

	xf.Id, err = strconv.ParseUint(xmlFile.Id, 10, 0)
	if err != nil {
		return
	}

	xf.Name = path.Join(dir, xmlFile.Name)

	xf.Info, err = xmlFileToFileInfo(xmlFile)
	if err != nil {
		return
	}

	if xf.Type == FileTypeFile && xmlFile.Data == nil {
		return
	}
	if xf.Type == FileTypeFile {
		xf.EncodingMimetype = xmlFile.Data.Encoding.Style
		xf.Size = xmlFile.Data.Size
		xf.length = xmlFile.Data.Length
		xf.offset = xmlFile.Data.Offset

		err = fileChecksumFromXml(&xf.CompressedChecksum, &xmlFile.Data.ArchivedChecksum)
		if err != nil {
			return
		}

		err = fileChecksumFromXml(&xf.ExtractedChecksum, &xmlFile.Data.ExtractedChecksum)
		if err != nil {
			return
		}
	}

	r.File[xf.Id] = xf

	if xf.Type == FileTypeDirectory {
		for _, subXmlFile := range xmlFile.File {
			err = r.readXmlFileTree(subXmlFile, xf.Name)
			if err != nil {
				return
			}
		}
	}

	return
}

// Open returns a ReadCloser that provides access to the file's
// uncompressed content.
func (f *File) Open() (rc io.ReadCloser, err error) {
	r := io.NewSectionReader(f.heap, f.offset, f.length)
	switch f.EncodingMimetype {
	case "application/octet-stream":
		rc = io.NopCloser(r)
	case "application/x-gzip":
		rc, err = zlib.NewReader(r)
	case "application/x-bzip2":
		rc = io.NopCloser(bzip2.NewReader(r))
	default:
		err = ErrFileEncodingUnsupported
	}

	return rc, err
}

// OpenRaw returns a ReadCloser that provides access to the file's
// raw content. The encoding of the raw content is specified in
// the File's EncodingMimetype field.
func (f *File) OpenRaw() (rc io.ReadCloser, err error) {
	rc = io.NopCloser(io.NewSectionReader(f.heap, f.offset, f.length))
	return
}

// Verify that the compressed content of the File in the
// archive matches the stored checksum.
func (f *File) VerifyChecksum() bool {
	// Non-files are implicitly OK, since all metadata
	// is stored in the TOC.
	if f.Type != FileTypeFile {
		return true
	}

	var hasher hash.Hash
	switch f.CompressedChecksum.Kind {
	case FileChecksumKindSHA1:
		hasher = sha1.New()
	case FileChecksumKindMD5:
		hasher = md5.New()
	default:
		return false
	}

	io.Copy(hasher, io.NewSectionReader(f.heap, f.offset, f.length))
	sum := hasher.Sum(nil)
	return bytes.Equal(sum, f.CompressedChecksum.Sum)
}

type WriterAtCloser interface {
	io.WriterAt
	io.Closer
	io.Writer
}

type Writer struct {
	File map[uint64]*File

	Certificates          []*x509.Certificate
	SigningKey            *rsa.PrivateKey
	SignatureCreationTime int64
	SignatureError        error

	xar           WriterAtCloser
	archiveOffset int64
	heapOffset    int64

	Toc *xmlXar
}

// OpenWriter will create the XAR file specified by name and return a Writer.
func OpenWriter(name string, privateKey *rsa.PrivateKey, certificates []*x509.Certificate) (*Writer, error) {
	f, err := os.Create(name)
	if err != nil {
		return nil, err
	}

	return NewWriter(f, privateKey, certificates)
}

// NewReader returns a new writer writing to w, which is assumed to have the given size in bytes.
func NewWriter(w WriterAtCloser, privateKey *rsa.PrivateKey, certificates []*x509.Certificate) (*Writer, error) {
	xw := &Writer{
		File:         make(map[uint64]*File),
		xar:          w,
		SigningKey:   privateKey,
		Certificates: certificates,
		Toc: &xmlXar{
			Toc: xmlToc{
				CreationTime: time.Now().Format(time.RFC3339),
				Checksum: &xmlChecksum{
					Style:  "sha1",
					Offset: 0,
					Size:   20,
				},
				File: make([]*xmlFile, 0),
			},
		},
		archiveOffset: 0,
	}

	xw.Toc.Toc.Signature = &xmlSignature{
		Offset: 20,
		Size:   256,
	}

	xw.heapOffset = xw.Toc.Toc.Checksum.Size + xw.Toc.Toc.Signature.Size

	if xw.SigningKey != nil && xw.Certificates != nil && len(xw.Certificates) > 0 {
		xw.Toc.Toc.SignatureCreationTime = float64(time.Now().Unix())
		xw.Toc.Toc.Signature.Style = "RSA"
		xw.Toc.Toc.Signature.Certificates = make([]string, len(xw.Certificates))

		for i, c := range xw.Certificates {
			xw.Toc.Toc.Signature.Certificates[i] = certToBase64PEM(c)
		}
	}

	return xw, nil
}

func certToBase64PEM(cert *x509.Certificate) string {
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Split the PEM string into lines
	lines := strings.Split(certPEM.String(), "\n")

	// Remove the first and last two lines ("BEGIN" and "END" lines)
	trimmedLines := lines[1 : len(lines)-2]

	// Join the remaining lines to obtain the certificate without headers
	return strings.Join(trimmedLines, "\n")
}

func (w *Writer) AddDirectory(archivedirectory string, shouldGzipFile bool) (err error) {
	err = filepath.Walk(archivedirectory, func(fileToAdd string, fileInfo os.FileInfo, err error) error {
		if archivedirectory == fileToAdd {
			return nil
		}

		fileTime, err := times.Stat(fileToAdd)
		if err != nil {
			return err
		}

		if fileInfo.IsDir() {
			nextId := uint64(len(w.File) + 1)

			file := &File{
				Id:   nextId,
				Name: archivedirectory,
				Type: FileTypeDirectory,
				Info: FsFileInfoToFileInfo(fileInfo, fileTime),
			}
			w.File[nextId] = file

			fileMetadata := &xmlFile{
				Id:    fmt.Sprintf("%d", file.Id),
				Name:  strings.Replace(fileToAdd, archivedirectory+"/", "", 1),
				Mode:  file.Info.Mode,
				Ctime: time.Unix(file.Info.Ctime, 0).Format(time.RFC3339),
				Atime: time.Unix(file.Info.Atime, 0).Format(time.RFC3339),
				Mtime: time.Unix(file.Info.Mtime, 0).Format(time.RFC3339),
				Type:  "directory",
				FinderCreateTime: &xmlFinderCreateTime{
					Time: time.Unix(file.Info.Ctime, 0).Format(time.RFC3339),
				},
			}
			w.Toc.Toc.File = append(w.Toc.Toc.File, fileMetadata)
			return nil
		} else {
			f, err := os.Open(fileToAdd)
			if err != nil {
				return err
			}

			if err = w.AddFile(strings.Replace(fileToAdd, archivedirectory+"/", "", 1), fileInfo, fileTime, f, shouldGzipFile); err != nil {
				return err
			}
		}

		return nil
	})

	return
}

func (w *Writer) AddFile(archiveFilename string, info fs.FileInfo, fileTime times.Timespec, f io.ReadSeekCloser, shouldGzipFile bool) (err error) {
	nextId := uint64(len(w.File) + 1)

	hasher := sha1.New()
	_, err = hashFileContent(f, hasher)
	if err != nil {
		return
	}
	extractedSha1ChecksumHash := hasher.Sum(nil)

	extractedFileChecksum := FileChecksum{
		Kind: FileChecksumKindSHA1,
		Sum:  extractedSha1ChecksumHash,
	}

	archivedFileChecksum := FileChecksum{
		Kind: FileChecksumKindSHA1,
	}

	file := &File{
		Id:                 nextId,
		Name:               archiveFilename,
		Type:               FileTypeFile,
		Info:               FsFileInfoToFileInfo(info, fileTime),
		CompressedChecksum: archivedFileChecksum,
		reader:             f,
		offset:             w.heapOffset,
		length:             info.Size(),
	}

	if shouldGzipFile {
		hasher := sha1.New()

		var compressedData bytes.Buffer
		gzw := gzip.NewWriter(&compressedData)
		_, err = io.Copy(gzw, f)
		if err != nil {
			return
		}

		file.reader = newNopSeeker(ioutil.NopCloser(&compressedData))

		var compressedFileSize int64
		compressedFileSize, err = hashFileContent(file.reader, hasher)
		if err != nil {
			return
		}
		file.EncodingMimetype = "application/x-gzip"
		extractedSha1ChecksumHash := hasher.Sum(nil)
		extractedFileChecksum.Sum = extractedSha1ChecksumHash
		file.Size = compressedFileSize
	} else {
		archivedFileChecksum.Sum = extractedFileChecksum.Sum
		file.EncodingMimetype = "application/octet-stream"
		file.Size = info.Size()
	}
	file.ExtractedChecksum = extractedFileChecksum

	w.File[nextId] = file

	fileMetadata := &xmlFile{
		Id:    fmt.Sprintf("%d", file.Id),
		Name:  file.Name,
		Mode:  file.Info.Mode,
		Gid:   file.Info.Gid,
		Uid:   file.Info.Uid,
		Ctime: time.Unix(file.Info.Ctime, 0).Format(time.RFC3339),
		Atime: time.Unix(file.Info.Atime, 0).Format(time.RFC3339),
		Mtime: time.Unix(file.Info.Mtime, 0).Format(time.RFC3339),
		Type:  "file",
		Data: &xmlFileData{
			Length: file.length,
			Size:   file.Size,
			Offset: file.offset,
			ArchivedChecksum: xmlFileChecksum{
				Style:  "sha1",
				Digest: hex.EncodeToString(file.CompressedChecksum.Sum),
			},
			ExtractedChecksum: xmlFileChecksum{
				Style:  "sha1",
				Digest: hex.EncodeToString(file.ExtractedChecksum.Sum),
			},
			Encoding: xmlFileEncoding{
				Style: file.EncodingMimetype,
			},
		},
		FinderCreateTime: &xmlFinderCreateTime{
			Time: time.Unix(file.Info.Ctime, 0).Format(time.RFC3339),
		},
	}
	w.Toc.Toc.File = append(w.Toc.Toc.File, fileMetadata)

	w.heapOffset += file.Size

	return nil
}

func FsFileInfoToFileInfo(info os.FileInfo, t times.Timespec) FileInfo {

	fi := FileInfo{
		Mode:  uint32(info.Mode()),
		Atime: t.AccessTime().Unix(),
		Mtime: t.ModTime().Unix(),
		Ctime: t.ChangeTime().Unix(),
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		fi.Gid = int(stat.Gid)
		fi.Uid = int(stat.Uid)
		fi.DeviceNo = uint64(stat.Dev)
		fi.Inode = uint64(stat.Ino)
	}

	return fi
}

func compressToc(tocObj *xmlXar) (toc, ztoc bytes.Buffer, err error) {
	encoder := xml.NewEncoder(&toc)
	err = encoder.Encode(tocObj)
	if err != nil {
		return
	}

	zlw := zlib.NewWriter(&ztoc)
	_, err = zlw.Write(toc.Bytes())
	if err != nil {
		return
	}
	err = zlw.Close()
	if err != nil {
		return
	}

	return
}

func writeHeaderAndToc(xar WriterAtCloser, toc *xmlXar, signingKey *rsa.PrivateKey, files map[uint64]*File) (offset int64, err error) {
	var tocBuf, ztocBuf bytes.Buffer
	tocBuf, ztocBuf, err = compressToc(toc)
	if err != nil {
		return
	}

	hdr := make([]byte, xarHeaderSize)
	binary.BigEndian.PutUint32(hdr[0:4], XarHeaderMagic)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(xarHeaderSize))
	binary.BigEndian.PutUint16(hdr[6:8], uint16(xarVersion))
	binary.BigEndian.PutUint64(hdr[8:16], uint64(ztocBuf.Len()))
	binary.BigEndian.PutUint64(hdr[16:24], uint64(tocBuf.Len()))
	binary.BigEndian.PutUint32(hdr[24:28], uint32(xarChecksumKindSHA1))

	// Write the header first
	_, err = xar.WriteAt(hdr, 0)
	if err != nil {
		return
	}

	// Write the zlib compressed TOC next
	_, err = xar.WriteAt(ztocBuf.Bytes(), xarHeaderSize)
	if err != nil {
		return
	}

	offset = xarHeaderSize + int64(ztocBuf.Len())

	// Calculate the checksum for the compressed toc and write it in the first 20 bytes on the heap
	hasher := crypto.SHA1.New()
	hasher.Write(ztocBuf.Bytes())
	tocChecksum := hasher.Sum(nil)

	checksumSectionWriter := NewSectionWriter(xar, offset, toc.Toc.Checksum.Size)
	if _, err = checksumSectionWriter.Write(tocChecksum); err != nil {
		return
	}
	offset += toc.Toc.Checksum.Size

	// Calculate the signature and write it in the next 20 bytes
	var signature []byte
	if signingKey != nil {
		signature, err = rsa.SignPKCS1v15(nil, signingKey, crypto.SHA1, tocChecksum)
		if err != nil {
			return
		}
	}
	sigSectionWriter := NewSectionWriter(xar, offset, toc.Toc.Signature.Size)
	if _, err = sigSectionWriter.Write(signature); err != nil {
		return
	}
	offset += toc.Toc.Signature.Size

	return
}

func (w *Writer) Write(data []byte) (n int, err error) {
	n, err = w.xar.WriteAt(data, w.archiveOffset)
	w.heapOffset += int64(n)
	return
}

// Close writes the header and heap to disk
func (w *Writer) Close() (err error) {

	w.archiveOffset, err = writeHeaderAndToc(w.xar, w.Toc, w.SigningKey, w.File)
	if err != nil {
		return
	}

	// Finally, write files into the archive heap
	for _, file := range w.File {

		if file.Type == FileTypeFile {
			_, err = file.reader.Seek(0, io.SeekStart)
			if err != nil {
				return
			}

			var fileContents []byte
			fileContents, err = readSeekCloserToBytes(file.reader)
			if err != nil {
				return
			}

			_, err = w.xar.WriteAt(fileContents, w.archiveOffset)
			if err != nil {
				return
			}

			err = file.reader.Close()
			if err != nil {
				return
			}

			w.archiveOffset += file.Size
		}
	}

	// if len(w.File) != len(w.Toc.Toc.File) {
	// 	err = fmt.Errorf("w.File length %d != TocFile length %d", len(w.File), len(w.Toc.Toc.File))
	// 	return
	// }

	err = w.xar.Close()

	return
}

func hashFileContent(reader io.ReadSeekCloser, hasher hash.Hash) (bytesRead int64, err error) {
	defer reader.Seek(0, io.SeekStart)

	var n int64
	if n, err = io.Copy(hasher, reader); err != nil {
		return
	} else {
		bytesRead += n
	}

	return
}

func readSeekCloserToBytes(reader io.ReadSeekCloser) ([]byte, error) {
	defer reader.Seek(0, io.SeekStart)

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return nil, fmt.Errorf("failed to copy data: %w", err)
	}

	return buf.Bytes(), nil
}

type SectionWriter struct {
	w        io.WriterAt
	off, lim int64
}

func NewSectionWriter(w io.WriterAt, off, n int64) *SectionWriter {
	return &SectionWriter{
		w:   w,
		off: off,
		lim: off + n,
	}
}

func (sw *SectionWriter) Write(p []byte) (n int, err error) {
	if sw.off >= sw.lim {
		return 0, errors.New("sectionwriter: end of section reached")
	}
	if int64(len(p)) > sw.lim-sw.off {
		p = p[:sw.lim-sw.off]
		err = errors.New("sectionwriter: write truncated")
	}
	n, werr := sw.w.WriteAt(p, sw.off)
	sw.off += int64(n)
	if werr != nil {
		err = werr
	}
	return
}

func newNopSeeker(r io.ReadCloser) io.ReadSeekCloser {
	return nopSeeker{r, r}
}

type nopSeeker struct {
	io.Reader
	io.Closer
}

func (nopSeeker) Seek(offset int64, whence int) (int64, error) { return int64(whence), nil }
