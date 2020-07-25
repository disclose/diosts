package securitytxt

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

type DomainClient struct {
	*Config

	client *http.Client
}

/*
4.1.  Web-based services

   Web-based services MUST place the security.txt file under the
   "/.well-known/" path; e.g. https://example.com/.well-known/
   security.txt as per [RFC8615].  For legacy compatibility, a
   security.txt file might be placed at the top-level path or redirect
   (as per section 6.4 of [RFC7231]) to the security.txt file under the
   "/.well-known/" path.  If a "security.txt" file is present in both
   locations, the one in the "/.well-known/" path MUST be used.

   Retrieval of "security.txt" files and resources indicated within such
   files may result in a redirect (as per section 6.4 of [RFC7231]).
   Researchers should perform additional triage (as per Section 6.1) to
   make sure these redirects are not malicious or point to resources
   controlled by an attacker.
*/
var schemas = []string{
	"https",
	"http",
}

var locations = []string{
	".well-known/security.txt",
	"security.txt",
}

func NewDomainClient(config *Config) (*DomainClient, error) {
	dialer := net.Dialer{
		Timeout: config.DialTimeout,
		KeepAlive: -1,
	}

	client := &http.Client{
		CheckRedirect: checkRedirect,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.Insecure,
			},
			Dial: dialer.Dial,
			TLSHandshakeTimeout: config.TLSHandshakeTimeout,
			DisableKeepAlives: true,
			MaxIdelConns: 1, // We only use connections for a single request
		},
		Timeout: config.RequestTimeout,
	}

	c := &DomainClient{
		Config: config,
		client: client,
	}

	return c, nil
}

func (c *DomainClient) GetSecurityTxt(domain string) (*SecurityTxt, error) {
	strippedDomain := stripDomain(domain)
	if strippedDomain != domain {
		log.Debug().Str("input", domain).Str("domain", strippedDomain).Msg("stripped domain")
	}

	body := c.GetDomainBody(strippedDomain)
	if body == nil {
		return nil, nil
	}

	return New(body)
}

// Iterate over valid endpoints and retrieve body
func (c *DomainClient) GetDomainBody(domain string) []byte {
	// security.txt endpoints in order of spec until we find one
	for _, schema := range(schemas) {
		for _, location := range(locations) {
			url := fmt.Sprintf("%s://%s/%s", schema, strippedDomain, location)
			body, err = c.GetBody(url)
			// TODO: If we have a body, return it, but record the error
			if err != nil {
				log.Debug().Err(err).Str("url", url).Msg("error retrieving")
				continue
			}
			if len(body) == 0 {
				log.Debug().Str("url", url).Msg("no body")
				continue
			}

			return body
		}
	}

	// Nothing found
	return nil
}

// Returning an error doesn't mean we don't have a body. If we can, we'll
// always read and return a body
func (c *DomainClient) GetBody(url string) ([]byte, error) {
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to retrieve %s, returned status %d", url, resp.StatusCode)
	}

	body := ioutil.ReadAll(resp.Body)
/* 
   It MUST have a Content-Type of "text/plain" with the
   default charset parameter set to "utf-8" (as per section 4.1.3 of
   [RFC2046]).
*/
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/plain; charset=utf/8" {
		log.Info().Str("content-type", contentType).Msg("Content-Type is not text/plain; charset=utf-8")
		return body, fmt.Errorf("expecting Content-Type of \"text/plain; charset=utf-8\", got \"%s\"", contentType)
	}

	return body, nil
}

// Get bare domain from input
func stripDomain(domain string) (string) {
	// Check for schema, strip if present
	if i := strings.Index(domain, "://"); i >= 0 {
		domain = domain[i+3:]
	}

	// Remove any path
	splits := strings.SplitN(domain, "/", 2)
	domain = splits[0]

	return domain
}

// Make sure we don't leave this domain - always log something
func checkRedirect(req *http.Request, via []*http.Request) error {
	from := via[len(via) - 1]
	log.Info().Str("from", from.URL.String()).Str("to", req.URL.String()).Msg("redirecting")

	fromHost := from.URL.Hostname()
	toHost := req.URL.Hostname()
	if fromHost != toHost {
		return fmt.Errorf("redirect from %s to %s, prohibiting redirect to different hostname", fromHost, toHost)
	}

	return nil
}
