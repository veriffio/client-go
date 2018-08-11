// Package proof implements a format to communicate and check existence proofs
/*
This package will typically not be used directly.

An existence proof is a way to show that a particular document A (stream of bytes)
was known at a particular point in time. By showing that another stream of bytes (B)
can be derived from the original stream of bytes through an unbroken chain of
one way functions (cryptographic hash functions) we can be sure that A must have
been known to know B.

By further showing that B has been published at publically available, trusted,
locations at a particular point in time we know with absolute certainty that A
must also have been known at that point in time.

The main type in this package is the Proof, a data structure intended to be
transmitted between creator and consumer. A Proof may be directly decoded from
its JSON representation. The client will then Verify that the proof is valide for
the particular data that he is interested in. Since the verification code is
publically available it may also be verified by the client if desired.

Please note that this package will not verify that the referred references really
contain the derived data stream. It is up to the client to decide which external
sources to trust and check that the data is published there.

See also the example in this package.
*/
package proof

import (
	"encoding/base64"
	"time"
)

// A Proof contains a slice of Data which is used as input to the operations.
// Each operation refers to the elements of the Data slice by using zero-based
// positive integers. The operations should be performed in sequential order and
// the output of the first operation may be referred to as -1, the second -2 etc.
// in the Operations, in that way a chain can be constructed.
type Proof struct {
	Operations []Operation `json:"operations,omitempty"`
	Data       [][]byte    `json:"data,omitempty"`
	References []Reference `json:"references,omitempty"`
}

// An Operation represents a hash operation of input data and is only used as part of
// a Proof.
type Operation struct {
	// Must equal one of the constants from this package
	Type string `json:"type"`
	// The input data to the hash operation is created by concatenating the slices of bytes
	// from the appended Proof.Data slice indexed by the indexes
	// in this slice. len(Data) must be larger than 0.
	Data []int `json:"data"`
}

// A Reference specifies the location where original or derived data is published.
type Reference struct {
	// Index into Proof.Data or calculated data as for a Operation
	Data int `json:"data"`
	// Approximate timestamp when this was published at the reference
	Timestamp time.Time `json:"timestamp"`
	// Descriptive reference to the source. For example an URL permalink
	Ref string `json:"ref"`
}

// A VerifiedReference is used to hold the output from Verify which may be checked
// to prove that the provided input data was known at the time of publication.
type VerifiedReference struct {
	data   []byte
	ref    string
	hashes []string
}

// Data returns the data that should be found at the reference.
func (vr VerifiedReference) Data() []byte {
	buf := make([]byte, len(vr.data))
	copy(buf, vr.data)
	return buf
}

// DataBase64 is a convenience method to get Data() as a string.
func (vr VerifiedReference) DataBase64() string {
	return base64.StdEncoding.EncodeToString(vr.data)
}

// Ref returns the string describing the location of publication.
func (vr VerifiedReference) Ref() string {
	return vr.ref
}

// HashFunctions returns a complete list of all HashFunctions that were used to
// construct the chain to the data used in this reference. This allows a client
// to discard any reference dependent on a hash function the client does not
// trust.
func (vr VerifiedReference) HashFunctions() []string {
	return vr.hashes
}
