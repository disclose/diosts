package securitytxt

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"unicode"

	"github.com/rs/zerolog/log"
)

type DomainClient struct {
	*Config

	client *http.Client
}

type DomainBody struct {
	url string
	body []byte
	err error
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

	c := &DomainClient{
		Config: config,
	}

	client := &http.Client{
		CheckRedirect: c.checkRedirect,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.Insecure,
			},
			Dial: dialer.Dial,
			TLSHandshakeTimeout: config.TLSHandshakeTimeout,
			DisableKeepAlives: true,
			MaxIdleConns: 1, // We only use connections for a single request
		},
		Timeout: config.RequestTimeout,
	}

	c.client = client

	return c, nil
}

func (c *DomainClient) GetSecurityTxt(domain string) (*SecurityTxt, error) {
	strippedDomain := stripDomain(domain)
	if strippedDomain != domain {
		log.Debug().Str("input", domain).Str("domain", strippedDomain).Msg("stripped domain")
	}

	body := c.GetDomainBody(strippedDomain)
	if body == nil {
		log.Info().Str("domain", strippedDomain).Msg("no security.txt found")
		return nil, nil
	}

	t, err := New(body.body)
	if err != nil {
		log.Info().Str("domain", strippedDomain).Err(err).Msg("error parsing security.txt")
		return nil, err
	}

	t.Domain = strippedDomain
	t.RetrievedFrom = body.url
	if body.err != nil {
		t.addError(body.err)
	}
	return t, nil
}

// Iterate over valid endpoints and retrieve body
func (c *DomainClient) GetDomainBody(domain string) (*DomainBody) {
	// security.txt endpoints in order of spec until we find one
	for _, schema := range(schemas) {
		for _, location := range(locations) {
			url := fmt.Sprintf("%s://%s/%s", schema, domain, location)
			body, err := c.GetBody(url)
			// No body means fatal retrieval error
			if body == nil {
				log.Debug().Err(err).Str("url", url).Msg("error retrieving")
				continue
			}

			// This is weird, ignore
			if len(body) == 0 {
				log.Debug().Str("url", url).Msg("no body")
				continue
			}

			return &DomainBody{
				url: url,
				body: body,
				err: err,
			}
		}
	}

	// Nothing found
	return nil
}

// Returning an error doesn't mean we don't have a body. If we can, we'll
// always read and return a body
func (c *DomainClient) GetBody(url string) ([]byte, error) {
	log.Debug().Str("url", url).Msg("retrieving")
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to retrieve %s, returned status %d", url, resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
/* 
   It MUST have a Content-Type of "text/plain" with the
   default charset parameter set to "utf-8" (as per section 4.1.3 of
   [RFC2046]).
*/
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/plain; charset=utf/8" {
		err = NewContentTypeError(contentType)
	}

	return body, err
}

// Make sure we don't leave this domain - always log something
func (c *DomainClient) checkRedirect(req *http.Request, via []*http.Request) error {
	from := via[len(via) - 1]
	log.Info().Str("from", from.URL.String()).Str("to", req.URL.String()).Msg("redirecting")

	if c.Config.StrictRedirect {
		fromHost := baseDomain(from.URL.Hostname())
		toHost := baseDomain(req.URL.Hostname())
		if fromHost != toHost {
			return NewRedirectError(fromHost, toHost)
		}
	}

	return nil
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

// Get the base domain name
func baseDomain(domain string) string {
	// Remove trailing "." - technically valid, but not needed in this case
	if domain[len(domain) - 1] == byte('.') {
		domain = domain[:len(domain) - 2]
	}

	splits := strings.Split(domain, ".")

	// This is just weird, but ok - probably ipv6 address
	if len(splits) < 2 {
		return domain
	}

	// Check if this is an IP or domain name; assuming TLD cannot
	// start with a number
	if unicode.IsDigit(rune(splits[len(splits) - 1][0])) {
		return domain
	}

	return strings.Join(splits[len(splits) - 2:], ".")
}
