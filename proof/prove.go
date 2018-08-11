package proof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"strconv"
)

// Verify verifies that the Proof contains a correct and un-broken chain of
// one-way funcations starting with data. If it does it will return a slice of
// VerifiedReferences that specify what data should be looked for where to
// complete the proof. If the Proof is not valid or the Proof does not contain
// any references that can be used for the particular input data an error is
// returned. If timestamp != 0 the references are also checked to include that.
func (p Proof) Verify(data []byte, timestamp int64) ([]VerifiedReference, error) {
	if data == nil || len(data) <= 0 {
		return nil, errors.New("no data to verify")
	}
	if p.Data == nil || len(p.Data) <= 0 {
		return nil, errors.New("no data in proof")
	}
	for i, v := range p.Data {
		if v == nil || len(v) < 1 {
			return nil, errors.New("data number " + strconv.Itoa(i) + " is empty")
		}
	}
	if p.References == nil || len(p.References) <= 0 {
		return nil, errors.New("no referene")
	}

	// to verify the proof we do the following:
	// 1. For each operation:
	//   a. Check that it uses a known type
	//   b. Check that it has non-empty input data
	//   c. Check that this input is not refering and undefined input
	//   d. Run the operation and append the output to the array of data
	// 2. For each reference:
	//   a. Check that the data is in the produced data array
	//   b. Check that the reference is not empty.
	//   c. Check that the input data is a child of this reference.
	//	 d. Also check that the timestep is included if provided

	tdata := []byte{}
	if timestamp != 0 {
		tdata = make([]byte, 8)
		binary.BigEndian.PutUint64(tdata, uint64(timestamp))
	}

	outData := [][]byte{}
	inBuf := make([]byte, 0, 512/8*2)

	for _, o := range p.Operations {
		op := operations[o.Type]
		if op == nil {
			return nil, errors.New("unknown operation '" + o.Type + "'")
		}
		if o.Data == nil || len(o.Data) <= 0 {
			return nil, errors.New("each operation mush have an input")
		}
		inBuf = inBuf[:0]
		for _, di := range o.Data {
			if di < 0 {
				if -di > len(outData) {
					return nil, errors.New("referencing a output not yet calculated " + strconv.Itoa(di))
				}
				i := -di - 1
				inBuf = append(inBuf, outData[i]...)
			} else if di < len(p.Data) {
				inBuf = append(inBuf, p.Data[di]...)
			} else {
				return nil, errors.New("refering to undefined data element " + strconv.Itoa(di))
			}
		}
		outData = append(outData, op(inBuf))
	}

	refData := make([]VerifiedReference, len(p.References))
	for ri, r := range p.References {
		if r.Ref == "" {
			return nil, errors.New("cannot have empty reference")
		}
		if r.Data < 0 {
			if -r.Data <= len(outData) {
				refData[ri] = VerifiedReference{
					data: outData[-r.Data-1],
					ref:  r.Ref,
				}
			} else {
				return nil, errors.New("reference refers to non-existing data " + strconv.Itoa(r.Data))
			}
		} else if r.Data < len(p.Data) {
			return nil, errors.New("reference must refer to calculated data")
		} else {
			return nil, errors.New("reference refers to non-existing data " + strconv.Itoa(r.Data))
		}
	}

	// now, for each of the verified references we have added we walk backwards to
	// check if it is dependent on the data we were given, if it is not we remove it
	// from our list since we cannot then trust it. Through this loop we will also collect
	// information about the hashes which were used to calculate it.

	refs := make([]VerifiedReference, 0, len(p.References))
	for ri, r := range p.References {
		if ok1, ok2, hashes := recData(p, data, tdata, r.Data); ok1 && (len(tdata) == 0 || ok2) {
			sort.Strings(hashes)
			refData[ri].hashes = hashes
			refs = append(refs, refData[ri])
		}
	}

	if len(refs) <= 0 {
		return nil, errors.New("the proof proves nothing for the input data")
	}

	return refs, nil
}

func recData(p Proof, data, tdata []byte, pos int) (bool, bool, []string) {
	if pos >= 0 {
		return bytes.Compare(data, p.Data[pos]) == 0, bytes.Compare(tdata, p.Data[pos]) == 0, []string{}
	}
	var o1, o2 bool
	h := map[string]struct{}{}
	for _, nPos := range p.Operations[-pos-1].Data {
		if okd, okt, hashes := recData(p, data, tdata, nPos); okd || okt {
			add := true
			for _, v := range hashes {
				if p.Operations[-pos-1].Type == v {
					add = false
					break
				}
			}
			if add {
				hashes = append(hashes, p.Operations[-pos-1].Type)
			}
			for _, hs := range hashes {
				h[hs] = struct{}{}
			}
			if okd {
				o1 = true
			}
			if okt {
				o2 = true
			}
		}
	}
	hashes := make([]string, 0, len(h))
	for k := range h {
		hashes = append(hashes, k)
	}
	return o1, o2, hashes
}
