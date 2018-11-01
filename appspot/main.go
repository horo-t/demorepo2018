// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"google.golang.org/appengine"
)

var (
	demo_domain_name  string
	demo_appspot_name string

	key_ec256   []byte
	certs_ec256 []byte
    
	origin_trial_token string
	hayabusa2_payload []byte
)

type Config struct {
	DemoDomainName   string `json:"demo_domain"`
	DemoAppSpotName  string `json:"demo_appspot"`
	EC256KeyFile     string `json:"ec256_key_file"`
	EC256CertFile    string `json:"ec256_cert_file"`
	OriginTrialToken string `json:"origin_trial_token"`
}

func init() {
	var config Config
	file, err := os.Open("config.json")
	defer file.Close()
	if err != nil {
		fmt.Println(err.Error())
	}
	jsonParser := json.NewDecoder(file)
	jsonParser.Decode(&config)

	demo_domain_name = config.DemoDomainName
	demo_appspot_name = config.DemoAppSpotName

	key_ec256, _ = ioutil.ReadFile(config.EC256KeyFile)
	certs_ec256, _ = ioutil.ReadFile(config.EC256CertFile)

	origin_trial_token = config.OriginTrialToken
	hayabusa2_payload,_ = ioutil.ReadFile("payload/hayabusa2.html")
}

func main() {
	http.HandleFunc("/cert/", certHandler)
	http.HandleFunc("/sxg/", signedExchangeHandler)
	http.HandleFunc("/", defaultHandler)
	appengine.Main()
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "404", 404)
}
