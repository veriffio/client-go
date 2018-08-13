// Package client implements a client using the veriff.io web api
package client

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/veriffio/client-go/proof"
	"golang.org/x/crypto/sha3"

	"github.com/veriffio/client-go/webapi"
)

// Defines the standard endpoint
const (
	DefaultEndpoint = "https://api.veriff.io/core"
)

var (
	ErrStatusReceived = errors.New("not yet provable, status received")
	ErrStatusInChain  = errors.New("not yet provable, status in chain")
	ErrStatusNotFound = errors.New("not yet provable, status not found")
)

// A Client represents a simplified way to interact with the proof.io web service.
// A client is not safe for concurrent use.
type Client struct {
	// If not nil requests will be sent here instead
	TestHandler http.Handler

	ep string
}

// New creates a new client connecting to the given endpoint. Use endpoint == "" for the
// default endpoint.
func New(endpoint string) *Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	return &Client{
		ep: endpoint,
	}
}

type req interface {
	Validate() error
}

// Add reads data until EOF, hashesh it and sends it to veriff.io.
func (c *Client) Add(data io.Reader) (token []byte, err error) {
	if data == nil {
		return nil, errors.New("data to be sent cannot be nil")
	}
	s2, s3, err := hashData(data)
	if err != nil {
		return nil, err
	}

	var resp webapi.AddResponse
	err = c.send(webapi.PathAdd, "POST", webapi.AddRequest{
		Sha2_256: s2,
		Sha3_512: s3,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return resp.Token, nil
}

// AddSlice works like Add but for a byte slice.
func (c *Client) AddSlice(data []byte) (id []byte, err error) {
	return c.Add(bytes.NewBuffer(data))
}

// Prove uses the token (returned from Add) to at a later point in time prove
// that data was added at the given point in time. If veriff.io is not trusted the
// client may check the external references returned to be sure. If the item
// has not yet been comitted to veriff.io or is in processing on of the errors
// defined in this package is returned.
func (c *Client) Prove(data io.Reader, token []byte) (res []proof.VerifiedReference, timestamp int64, errs error) {
	if data == nil {
		return nil, 0, errors.New("must provide some data to prove")
	}
	s2, s3, err := hashData(data)
	if err != nil {
		return nil, 0, err
	}
	if token == nil {
		return nil, 0, errors.New("must have a token")
	}
	var pr webapi.ProveRequest
	if len(token) != 16 {
		return nil, 0, errors.New("incorrect token provided")
	}
	pr.Token = token
	pr.Sha2_256 = s2

	var r webapi.ProveResponse
	err = c.send(webapi.PathProve, "POST", pr, &r)
	if err == ErrStatusNotFound {
		return nil, 0, ErrStatusNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	// verify the proof locally and verify that the input used in the proof correspond to the
	// input we expect based on the hashes we have computed from the data
	if bytes.Compare(s2, r.Sha2_256) != 0 {
		return nil, 0, errors.New("the hash does not match, did you add inconsistent hashes? (sha2_256)")
	}
	if bytes.Compare(s3, r.Sha3_512) != 0 {
		return nil, 0, errors.New("the hash does not match, did you add inconsistent hashes? (sha3_512)")
	}

	switch r.Status {
	case webapi.StatusProvable:
		break
	case webapi.StatusReceived:
		return nil, 0, ErrStatusReceived
	case webapi.StatusInChain:
		return nil, 0, ErrStatusInChain
	default:
		return nil, 0, errors.New("unknown proof status: " + r.Status)
	}

	ts, err := strconv.ParseInt(r.Timestamp, 10, 64)
	if err != nil {
		return nil, 0, errors.New("bad timestamp returned by server")
	}

	refs, err := r.Proof.Verify(s2, ts)
	if err != nil {
		return nil, 0, err
	}
	refs2, err := r.Proof.Verify(s3, ts)
	if err != nil {
		return nil, 0, err
	}
	return append(refs, refs2...), ts, nil
}

func (c *Client) ProveSlice(data, id []byte) ([]proof.VerifiedReference, int64, error) {
	return c.Prove(bytes.NewBuffer(data), id)
}

func (c *Client) Latest() (sha2, sha3 []byte, ts time.Time, err error) {

	var r webapi.LatestResponse
	err = c.send(webapi.PathLatest, "POST", nil, &r)
	if err != nil {
		return
	}

	no, err := strconv.ParseInt(r.Timestamp, 10, 64)
	if err != nil {
		return
	}
	ts = time.Unix(0, no)

	return r.Sha2_256, r.Sha3_512, ts, err
}

func (c *Client) Fixpoints() (fps []webapi.Fixpoint, err error) {
	var r webapi.FixpointsResponse
	err = c.send(webapi.PathFixpoints, "POST", nil, &r)
	if err != nil {
		return
	}
	if r.Points == nil {
		return nil, errors.New("empty response returned")
	}
	return r.Points, nil
}

// do sha256 and sha3 hash of the data
func hashData(data io.Reader) ([]byte, []byte, error) {
	h2 := sha256.New()
	r := io.TeeReader(data, h2)
	h3 := sha3.New512()
	n, err := io.Copy(h3, r)
	if n <= 0 {
		return nil, nil, errors.New("cannot use empty data")
	}
	s2 := h2.Sum(nil)
	s3 := h3.Sum(nil)
	return s2, s3, err
}
