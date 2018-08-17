// Package webapi defines the api exposed by the veriff.io service
package webapi

/*
This package will typically not be used directly
*/

import (
	"errors"

	"github.com/veriffio/client-go/proof"
)

// Each item can been in one of three different states as described by these constants.
const (
	// The item has been recieved by the veriff.io service, but is not yet finally comitted to storage.
	StatusReceived = "received"
	// The item has been stored by the server but there are as of yet no external references published.
	StatusInChain = "chained"
	// The item is stored in the chain and have references publised at external sources.
	StatusProvable = "provable"
)

// Paths where the different endpoints can be found.
const (
	PathAdd       = "add"
	PathProve     = "prove"
	PathLatest    = "latest"
	PathFixpoints = "fixpoints"
	PathHistory   = "history"
)

// An AddRequest must contain both the sha2 and sha3 hash of the data. It is the clients
// responsibility to ensure that they match. Any obviously non-hashes will be rejected.
// If non-matching hashes are given any subsequent existance proof request will fail.
type AddRequest struct {
	Sha2_256 []byte `json:"sha2_256"`
	Sha3_512 []byte `json:"sha3_512"`
}

// Validate performs sanity checks on the request.
func (ar AddRequest) Validate() error {
	if ar.Sha2_256 == nil || len(ar.Sha2_256) != 32 {
		return errors.New("the sha2_256 hash must be specified as a valid hash")
	}
	if ar.Sha3_512 == nil || len(ar.Sha3_512) != 64 {
		return errors.New("the sha3_512 hash must be specified as a valid hash")
	}
	return nil
}

// An AddResponse returns a secret token. This token togeather with the hash of
// the file can later be used to retrieve a existance proof for the file and should
// thus be kept private.
type AddResponse struct {
	Token                []byte `json:"token"`
	ApproximateTimestamp string `json:"approximate_timestamp"`
	Sha2_256             []byte `json:"sha2_256"`
	Sha3_512             []byte `json:"sha3_512"`
}

// A ProveRequest must contain both the hash and the secret token (proving you are the originator).
type ProveRequest struct {
	Token    []byte `json:"token"`
	Sha2_256 []byte `json:"sha2_256"`
}

// Validate performs sanity checks on the request
func (pr ProveRequest) Validate() error {
	if pr.Token == nil || pr.Sha2_256 == nil || len(pr.Token) < 1 {
		return errors.New("must specify token and hash")
	}
	if len(pr.Sha2_256) != 32 {
		return errors.New("must specify a hash of correct length")
	}
	return nil
}

// A ProveResponse returns a proof that the given item, as given by the two hashes, was stored at
// the given time which can be verified by checking the Proof and the references it refers to.
// The first element in Prove.Data should be checked to equal the (bytewise) concatenation
// [Timestamp, Sha2_256, Sha3_512].
type ProveResponse struct {
	Timestamp string      `json:"timestamp,omitempty"`
	Sha2_256  []byte      `json:"sha2_256,omitempty"`
	Sha3_512  []byte      `json:"sha3_512,omitempty"`
	Proof     proof.Proof `json:"proof,omitempty"`
	Status    string      `json:"status,omitempty"`
}

// LatestResponse type returned from the PathLatest endpoint that represents the latest
// state of the chain.
type LatestResponse struct {
	Timestamp string `json:"timestamp,omitempty"`
	Sha2_256  []byte `json:"sha2_256"`
	Sha3_512  []byte `json:"sha3_512,omitempty"`
}

// FixpointsResponse is returned from the PathFixpoints endpoint.
type FixpointsResponse struct {
	Points []Fixpoint `json:"fixpoints"`
}

// Fixpoint represents one fixpoint stored in the server itself.
type Fixpoint struct {
	Timestamp string `json:"timestamp"`
	Sha2_256  []byte `json:"sha2_256"`
	Sha3_512  []byte `json:"sha3_512"`
}
