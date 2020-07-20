package securitytxt

// For now, this check is the input is a valid PGP clearsign message. If there
// is no valid armored structure found, Signed() is false and Message() returns
// the input. If the message is valid, Signed() is true and Message() returns
// the message text itself.

// This DOES NOT verify the signature (yet)

import (
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
)

type SignedMessage struct {
	message []byte
	signed bool
}

func NewSignedMessage(in []byte) (*SignedMessage, error) {
	// Check clearsign structure and extract parts
	block, rest := clearsign.Decode(in)
	if block == nil {
		m := &SignedMessage{
			message: rest,
			signed: false,
		}
		return m, nil
	}

	// Check and extract signature
	p, err := packet.Read(block.ArmoredSignature.Body)
	if err != nil {
		return nil, err
	}

	// TODO: verify signature

	m := &SignedMessage{
		message: block.Bytes,
		signed: true,
	}

	return m
}

func (m *SignedMessage) Signed() bool {
	return m.signed
}

func (m *SignedMessage) Message() []byte {
	return m.message
}
