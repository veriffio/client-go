package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path"
	"strconv"
)

// convenience method for sending a request, handling needed headers etc.
func (c *Client) send(pth string, method string, data req, resp interface{}) error {

	var buf []byte
	var err error
	if data != nil {
		if err := data.Validate(); err != nil {
			return err
		}
		buf, err = json.Marshal(data)
		if err != nil {
			return err
		}
	} else {
		buf = []byte{}
	}

	var req *http.Request
	if c.TestHandler == nil {
		req, err = http.NewRequest(method, path.Join(c.ep, pth), bytes.NewBuffer(buf))
		if err != nil {
			return err
		}
	} else {
		tp := c.ep + "/" + pth
		req = httptest.NewRequest(method, tp, bytes.NewBuffer(buf))
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client", "client-go")

	var re *http.Response
	if c.TestHandler == nil {
		client := http.Client{}
		re, err = client.Do(req)
		if err != nil {
			return err
		}
	} else {
		rec := httptest.NewRecorder()
		c.TestHandler.ServeHTTP(rec, req)
		re = rec.Result()
	}

	// Read out the body
	defer re.Body.Close()
	body, err := ioutil.ReadAll(re.Body)
	if err != nil {
		return err
	}

	// 404 is special cased as it may be returned before it has been handled,
	// although rarely it could happen
	if re.StatusCode == http.StatusNotFound {
		return ErrStatusNotFound
	}

	// If the status is ok we should be able to parse out the response
	if re.StatusCode == 200 {
		return json.Unmarshal(body, resp)
	}
	if re.StatusCode == 400 {
		type e struct {
			Error string
		}
		var ee e
		err := json.Unmarshal(body, &ee)
		if err != nil {
			return err
		}
		return errors.New("400:" + ee.Error)
	}
	return errors.New("unexpected response code " + strconv.Itoa(re.StatusCode) + " " + req.URL.String())
}
