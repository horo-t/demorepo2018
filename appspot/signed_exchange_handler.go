// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/WICG/webpackage/go/signedexchange"
	"github.com/WICG/webpackage/go/signedexchange/version"
)

const defaultPayload = `<!DOCTYPE html>
<html>
  <head>
    <title>Hello SignedHTTPExchange</title>
  </head>
  <body>
    <div id="message">
      <h1>Hello SignedHTTPExchange</h1>
    </div>
  </body>
</html>
`

type exchangeParams struct {
	ver               version.Version
	contentUrl        string
	certUrl           string
	validityUrl       string
	pemCerts          []byte
	pemPrivateKey     []byte
	contentType       string
	payload           []byte
	linkPreloadString string
	date              time.Time
}

func createExchange(params *exchangeParams) (*signedexchange.Exchange, error) {
	certUrl, _ := url.Parse(params.certUrl)
	validityUrl, _ := url.Parse(params.validityUrl)
	certs, err := signedexchange.ParseCertificates(params.pemCerts)
	if err != nil {
		return nil, err
	}
	if certs == nil {
		return nil, errors.New("invalid certificate")
	}
	parsedPrivKey, _ := pem.Decode(params.pemPrivateKey)
	if parsedPrivKey == nil {
		return nil, errors.New("invalid private key")
	}
	privkey, err := signedexchange.ParsePrivateKey(parsedPrivKey.Bytes)
	if err != nil {
		return nil, err
	}
	if privkey == nil {
		return nil, errors.New("invalid private key")
	}
	parsedUrl, err := url.Parse(params.contentUrl)
	if err != nil {
		return nil, errors.New("failed to parse URL")
	}
	reqHeader := http.Header{}
	resHeader := http.Header{}
	resHeader.Add("content-type", params.contentType)

	if params.linkPreloadString != "" {
		resHeader.Add("link", params.linkPreloadString)
	}

	e, err := signedexchange.NewExchange(params.ver, parsedUrl, reqHeader, 200, resHeader, []byte(params.payload))
	if err != nil {
		return nil, err
	}
	if err := e.MiEncodePayload(4096); err != nil {
		return nil, err
	}

	s := &signedexchange.Signer{
		Date:        params.date,
		Expires:     params.date.Add(time.Hour * 24),
		Certs:       certs,
		CertUrl:     certUrl,
		ValidityUrl: validityUrl,
		PrivKey:     privkey,
	}
	if s == nil {
		return nil, errors.New("Failed to sign")
	}
	if err := e.AddSignatureHeader(s); err != nil {
		return nil, err
	}
	return e, nil
}

func contentType(v version.Version) string {
	switch v {
	case version.Version1b1:
		return "application/signed-exchange;v=b1"
	case version.Version1b2:
		return "application/signed-exchange;v=b2"
	default:
		panic("not reached")
	}
}

func versionFromAcceptHeader(accept string) (version.Version, error) {
	for _, t := range strings.Split(accept, ",") {
		s := strings.TrimSpace(t)
		if strings.HasPrefix(s, "application/signed-exchange;v=b1") {
			return version.Version1b1, nil
		}
		if strings.HasPrefix(s, "application/signed-exchange;v=b2") {
			return version.Version1b2, nil
		}
	}
    return version.Version1b2, nil
}

func serveExchange(params *exchangeParams, q url.Values, w http.ResponseWriter) {
	e, err := createExchange(params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentType(params.ver))
    w.Header().Set("Origin-Trial", origin_trial_token)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	e.Write(w)
}

func signedExchangeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ver, ok := version.Parse(q.Get("v"))
	if !ok {
		var err error
		ver, err = versionFromAcceptHeader(r.Header.Get("accept"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	params := &exchangeParams{
		ver:               ver,
		contentUrl:        "https://" + demo_domain_name + "/hello_ec.html",
		certUrl:           "https://" + demo_appspot_name + "/cert/ec256",
		validityUrl:       "https://" + demo_domain_name + "/cert/null.validity.msg",
		pemCerts:          certs_ec256,
		pemPrivateKey:     key_ec256,
		contentType:       "text/html; charset=utf-8",
		payload:           []byte(defaultPayload),
		linkPreloadString: "",
		date:              time.Now().Add(-time.Second * 10),
	}

	switch r.URL.Path {
	case "/sxg/hayabusa2.sxg":
		params.contentUrl = "https://" + demo_domain_name + "/hayabusa2.html"
		params.payload = hayabusa2_payload
		serveExchange(params, q, w)
	default:
		http.Error(w, "signedExchangeHandler", 404)
	}
}
