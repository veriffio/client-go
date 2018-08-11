package proof

import (
	"encoding/json"
	"fmt"
)

func ExampleProof() {
	data := []byte(`{
		"operations":[{
				"type": "sha3_512",
				"data": [0]
			},{
				"type":"sha2_256",
				"data": [-1,0]}],
		"data": [
			"AQIDBAUGBwgJCgsMDQ4PEBESExQ="],
		"references": [{
				"data":-2,
				"ref":"encyclopedia britannica"}]}`)

	var p Proof
	json.Unmarshal(data, &p)
	vr, err := p.Verify(p.Data[0], 0)
	if err != nil {
		fmt.Println("proof not consistent: ", err)
	}
	fmt.Println("The data", "'"+vr[0].DataBase64()+"'", "should be found in", "'"+vr[0].Ref()+"'")
	// Output: The data 'avaZW1398UuMUV9tirLTXlc4XpjNeV5D9cTAZje0nNw=' should be found in 'encyclopedia britannica'
}
