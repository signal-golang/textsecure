// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package transport

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/signal-golang/textsecure/rootCa"

	log "github.com/sirupsen/logrus"
)

var Transport Transporter

func SetupTransporter(server string,
	tel string,
	password string,
	userAgent string,
	proxyServer string) {
	Transport = newHTTPTransporter(server, tel, password, userAgent, proxyServer)
}

type response struct {
	Status int
	Body   io.ReadCloser
}

func (r *response) IsError() bool {
	return r.Status < 200 || r.Status >= 300
}

func (r *response) Error() string {
	return fmt.Sprintf("status code %d\n", r.Status)
}

type Transporter interface {
	Get(url string) (*response, error)
	Del(url string) (*response, error)
	Put(url string, body []byte, ct string) (*response, error)
	PutJSON(url string, body []byte) (*response, error)
	PutBinary(url string, body []byte) (*response, error)
}

type httpTransporter struct {
	baseURL     string
	user        string
	pass        string
	proxyServer string
	userAgent   string
	client      *http.Client
}

// func getProxy(req *http.Request) (*url.URL, error) {
// 	if config.ProxyServer != "" {
// 		u, err := url.Parse(config.ProxyServer)
// 		if err == nil {
// 			return u, nil
// 		}
// 	}
// 	return http.ProxyFromEnvironment(req)
// }

func NewHTTPClient() *http.Client {
	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 30 * time.Second,
		},
		Timeout: 45 * time.Second,
	}

	return client
}

var CdnTransport *httpTransporter

func SetupCDNTransporter(cdnUrl string, tel string, password string, userAgent string, proxyServer string) {
	// setupCA()
	CdnTransport = newHTTPTransporter(cdnUrl, tel, password, userAgent, proxyServer)
}
func newHTTPTransporter(baseURL, user, pass string, userAgent string, proxyServer string) *httpTransporter {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootCa.RootCA},
			// Proxy:           getProxy,
		},
	}

	return &httpTransporter{baseURL, user, pass, userAgent, proxyServer, client}
}

func (ht *httpTransporter) Get(url string) (*response, error) {
	req, err := http.NewRequest("GET", ht.baseURL+url, nil)
	if err != nil {
		return nil, err
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("GET %s %d\n", url, r.Status)

	return r, err
}

func (ht *httpTransporter) Del(url string) (*response, error) {
	req, err := http.NewRequest("DELETE", ht.baseURL+url, nil)
	if err != nil {
		return nil, err
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("DELETE %s %d\n", url, r.Status)

	return r, err
}

func (ht *httpTransporter) Put(url string, body []byte, ct string) (*response, error) {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PUT", ht.baseURL+url, br)
	if err != nil {
		return nil, err
	}
	if ht.userAgent != "" {
		req.Header.Set("X-Signal-Agent", ht.userAgent)
	}
	req.Header.Add("Content-Type", ct)
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("[textsecure] PUT %s %d\n", url, r.Status)

	return r, err
}

func (ht *httpTransporter) PutJSON(url string, body []byte) (*response, error) {
	return ht.Put(url, body, "application/json")
}

func (ht *httpTransporter) PutBinary(url string, body []byte) (*response, error) {
	return ht.Put(url, body, "application/octet-stream")
}
