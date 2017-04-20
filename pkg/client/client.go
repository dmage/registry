package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/docker/libtrust"
)

type Client struct {
	host       string
	creds      auth.CredentialStore
	transport  http.RoundTripper
	httpClient *http.Client
	insecure   bool
}

func New(host string, creds auth.CredentialStore, transport http.RoundTripper, insecure bool) *Client {
	return &Client{
		host:      host,
		creds:     creds,
		transport: transport,
		httpClient: &http.Client{
			Transport: transport,
		},
		insecure: insecure,
	}
}

func (c *Client) uri(format string, a ...interface{}) *url.URL {
	scheme := "https"
	if c.insecure {
		scheme = "http"
	}
	return &url.URL{
		Scheme: scheme,
		Host:   c.host,
		Path:   fmt.Sprintf(format, a...),
	}
}

func (c *Client) client(scope string, actions ...string) (*http.Client, error) {
	resp, err := c.httpClient.Get(c.uri("/v2/").String())
	if err != nil {
		return nil, fmt.Errorf("create client: get challenges from /v2/: %s", err)
	}
	defer resp.Body.Close()

	manager := challenge.NewSimpleManager()
	if err := manager.AddResponse(resp); err != nil {
		return nil, fmt.Errorf("create client: add response to challenge manager: %s", err)
	}

	authorizer := auth.NewAuthorizer(
		manager,
		auth.NewTokenHandler(c.transport, c.creds, scope, actions...),
	)

	rt := transport.NewTransport(c.transport, authorizer)
	return &http.Client{
		Transport: rt,
	}, nil
}

func (c *Client) Token(scope string) (string, error) {
	uri := c.uri("/v2/")

	resp, err := c.httpClient.Get(uri.String())
	if err != nil {
		return "", err
	}
	resp.Body.Close()

	challenges := challenge.ResponseChallenges(resp)
	if len(challenges) != 1 {
		return "", fmt.Errorf("unexpected challenges value: %v", challenges)
	}

	challenge := challenges[0]
	if challenge.Scheme != "bearer" {
		return "", fmt.Errorf("unexpected challenge scheme: %v", challenge.Scheme)
	}

	realm, ok := challenge.Parameters["realm"]
	if !ok {
		return "", fmt.Errorf("no realm parameter in the challenge")
	}

	params := url.Values{}
	if service, ok := challenge.Parameters["service"]; ok {
		params["service"] = []string{service}
	}
	if scope != "" {
		params["scope"] = []string{scope}
	}

	uri, err = url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("parse realm: %s", err)
	}

	req, err := http.NewRequest("GET", realm+"?"+params.Encode(), nil)
	if err != nil {
		return "", err
	}

	username, password := "", ""
	if c.creds != nil {
		username, password = c.creds.Basic(uri)
	}
	if username != "" || password != "" {
		userpass := fmt.Sprintf("%s:%s", username, password)
		token := base64.StdEncoding.EncodeToString([]byte(userpass))
		req.Header.Add("Authorization", "Basic "+token)
	}

	resp, err = c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", resp.Status)
	}

	var v struct {
		Token string
	}
	err = json.NewDecoder(resp.Body).Decode(&v)
	if err != nil {
		return "", err
	}

	return v.Token, nil
}

func removeEmptyElements(arr []string) []string {
	out := 0
	for i, x := range arr {
		if x == "" {
			continue
		}
		if i != out {
			arr[out] = arr[i]
		}
		out++
	}
	return arr[:out]
}

func (c *Client) Get(path string) error {
	parts := removeEmptyElements(strings.Split(path, "/"))
	if len(parts) >= 1 && parts[0] == "v2" {
		if len(parts) >= 4 && (parts[len(parts)-2] == "manifests" || parts[len(parts)-2] == "blobs") {
			scope := strings.Join(parts[1:len(parts)-2], "/")
			return c.get(scope, strings.Join(parts[len(parts)-2:], "/"))
		}
	}
	return fmt.Errorf("unsupported path: %s", path)
}

func (c *Client) Put(path string) error {
	parts := removeEmptyElements(strings.Split(path, "/"))
	if len(parts) >= 1 && parts[0] == "v2" {
		if len(parts) >= 4 && parts[len(parts)-2] == "blobs" && parts[len(parts)-1] == "uploads" {
			scope := strings.Join(parts[1:len(parts)-2], "/")
			digest, err := c.UploadBlob(scope, os.Stdin)
			if err != nil {
				return err
			}
			fmt.Printf("/v2/%s/blobs/%s\n", scope, digest)
			return nil
		}
		if len(parts) >= 4 && parts[len(parts)-2] == "manifests" {
			scope := strings.Join(parts[1:len(parts)-2], "/")
			reference := parts[len(parts)-1]
			return c.UploadManifest(scope, reference, os.Stdin)
		}
	}
	return fmt.Errorf("unsupported path: %s", path)
}

func (c *Client) get(scope, subpath string) error {
	client, err := c.client(scope, "pull")
	if err != nil {
		return err
	}

	resp, err := client.Get(c.uri("/v2/%s/%s", scope, subpath).String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) UploadBlob(scope string, content io.Reader) (string, error) {
	client, err := c.client(scope, "push", "pull")
	if err != nil {
		return "", err
	}

	resp, err := client.Post(c.uri("/v2/%s/blobs/uploads/", scope).String(), "", nil)
	if err != nil {
		return "", err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("%s", resp.Status)
	}

	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("no Location header")
	}

	uri, err := url.Parse(loc)
	if err != nil {
		return "", fmt.Errorf("parse Location: %s", err)
	}

	if uri.RawQuery != "" {
		uri.RawQuery += "&"
	}

	data, err := ioutil.ReadAll(content)
	if err != nil {
		return "", err
	}

	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	uri.RawQuery += "digest=" + digest

	req, err := http.NewRequest("PUT", uri.String(), bytes.NewReader(data))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/octet-stream")

	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("%s", resp.Status)
	}

	return digest, nil
}

func (c *Client) UploadManifest(scope string, reference string, content io.Reader) error {
	client, err := c.client(scope, "push", "pull")
	if err != nil {
		return err
	}

	data, err := ioutil.ReadAll(content)
	if err != nil {
		return err
	}

	pk, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		return fmt.Errorf("generate private key for signature: %sv", err)
	}

	js, err := libtrust.NewJSONSignature(data)
	if err != nil {
		return fmt.Errorf("create json signature: %s", err)
	}

	if err := js.Sign(pk); err != nil {
		return fmt.Errorf("sign manifest: %s", err)
	}

	pretty, err := js.PrettySignature("signatures")
	if err != nil {
		return err
	}

	log.Println("Signed manifest:", string(pretty))

	req, err := http.NewRequest("PUT", c.uri("/v2/%s/manifests/%s", scope, reference).String(), bytes.NewReader(pretty))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/vnd.docker.distribution.manifest.v1+json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := ioutil.ReadAll(resp.Body)
		if len(body) > 0 {
			log.Println(string(body))
		}
		return fmt.Errorf("%s", resp.Status)
	}

	return nil
}
