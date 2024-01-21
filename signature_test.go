package xar_test

import (
	"strings"
	"testing"

	xar "github.com/korylprince/goxar"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sigTest struct {
	file     string
	sigErr   bool
	xSigErr  bool
	appleErr bool
}

var sigTests = []sigTest{
	{
		file:     "testdata/valid.pkg",
		sigErr:   false,
		xSigErr:  false,
		appleErr: false,
	},
	{
		file:     "testdata/bad_signature.pkg",
		sigErr:   true,
		xSigErr:  false,
		appleErr: false,
	},
	{
		file:     "testdata/bad_x_signature.pkg",
		sigErr:   false,
		xSigErr:  true,
		appleErr: true,
	},
	{
		file:     "testdata/bad_both.pkg",
		sigErr:   true,
		xSigErr:  true,
		appleErr: true,
	},
}

func TestSignature(t *testing.T) {
	for _, test := range sigTests {
		t.Run(strings.Split(test.file, "/")[1], func(t *testing.T) {
			r, err := xar.OpenReader(test.file)
			require.NoError(t, err)
			assert.Truef(t, test.sigErr != (r.SignatureError == nil), "expected signature error: %v, got: %v", test.sigErr, r.SignatureError)
			assert.Truef(t, test.xSigErr != (r.XSignatureError == nil), "expected x-signature error: %v, got: %v", test.xSigErr, r.XSignatureError)
			assert.Truef(t, test.appleErr != (r.VerifyApplePkg() == nil), "expected apple error: %v, got: %v", test.appleErr, r.VerifyApplePkg())
		})
	}
}
