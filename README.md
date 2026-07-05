<div align="center">

<a href="https://disclose.io"><img src="docs/marquee.png" alt="diosts · disclose.io" width="820"></a>

# diosts

### Validate `security.txt` at Internet scale — a fast **Go** scraper for [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) that keeps the directory fresh.

<p>
<a href="LICENSE"><img src="https://img.shields.io/github/license/disclose/diosts?color=5B3AB6&label=license" alt="license"></a>
<img src="https://img.shields.io/badge/lang-Go-5B3AB6" alt="lang Go">
<a href="https://www.rfc-editor.org/rfc/rfc9116"><img src="https://img.shields.io/badge/spec-RFC%209116-5B3AB6" alt="spec RFC%209116"></a>
<a href="https://github.com/disclose/diosts/issues"><img src="https://img.shields.io/badge/PRs-welcome-5B3AB6" alt="PRs welcome"></a>
</p>

*Part of **[the disclose.io Project](https://disclose.io)** — the open, vendor-neutral infrastructure for vulnerability disclosure. [Browse the ecosystem →](https://github.com/disclose)*

</div>

---


# diosts

The disclose.io security.txt scraper (`diosts`) takes a list of domains as the input, retrieves and validates the `security.txt` if available and outputs it in the disclose.io JSON format.

## Installation

### Prerequisites:
- Go 1.22 or newer

### Option 1: Using go install (recommended)
```bash
# Install the latest version (v0.2.3)
go install github.com/disclose/diosts/cmd/diosts@latest

# The binary will be installed to your $GOPATH/bin directory
# Make sure this is in your PATH to run diosts from anywhere
```

### Option 2: From source
```bash
# Clone the repository
git clone https://github.com/disclose/diosts.git
cd diosts

# Build the binary
go build ./cmd/diosts

# Optional: Install to your $GOPATH/bin
go install ./cmd/diosts
```

## Usage
```bash
cat domains.txt | diosts -t <threads> -n <non-compliant-output> 2>diosts.log >securitytxt.json
```

This will try and scrape the `security.txt` from the domains listed in `domains.txt`, with `<threads>` parallel threads (defaults to 8). Logging (with information on each of the domains in the input) will be written to `diosts.log` (because it's output to `stderr`) and a JSON array of retrieved `security.txt` information in disclose.io format will be written to `securitytxt.json`.

The `-n` or `--non-compliant` flag enables you to output the non-RFC-compliant security.txt files to a separate JSON file for further analysis and processing.

For each input, the following URIs are tried, in order:
1. `https://<domain>/.well-known/security.txt`
2. `https://<domain>/security.txt`
3. `http://<domain>/.well-known/security.txt`
4. `http://<domain>/security.txt`

Any non-fatal violations of the [`security.txt` specification](https://www.rfc-editor.org/rfc/rfc9116) will be logged and tracked in the output.

## Supported Fields

The tool supports all fields defined in RFC 9116 plus extensions:

| Field | Required | Description |
|-------|----------|-------------|
| Contact | Yes | Contact information for reporting security issues |
| Expires | Yes | Date after which the security.txt file should be considered stale |
| Encryption | No | Link to encryption key for secure communication |
| Acknowledgments | No | Link to a page where security researchers are recognized |
| Policy | No | Link to the security policy |
| Hiring | No | Link to security-related job positions |
| Preferred-Languages | No | Languages the security team understands |
| Canonical | No | The canonical URIs where the security.txt file is located |
| CSAF | No | Link to the provider-metadata.json of the CSAF (Common Security Advisory Framework) provider |

## RFC 9116 Compliance

The tool checks and reports:
- Whether a security.txt file is RFC compliant
- Specific compliance issues found
- Required-field presence for `Contact` and `Expires`
- Expired `Expires` values
- Common field-value issues such as insecure canonical URLs, malformed contact URIs, and invalid preferred-language tags

## Notes

### Redirects

According to the specifications, a redirect should be followed when retrieving `security.txt`. However:

> When retrieving the file and any resources referenced in the file,
> researchers should record any redirects since they can lead to a
> different domain or IP address controlled by an attacker.  Further
> inspections of such redirects is recommended before using the
> information contained within the file.

By default, redirects are followed and recorded in the output metadata. With `--strict-redirect`, redirects are limited to the same registrable domain (for example, `www.google.com` and `google.com` are treated as the same base domain).

### Canonical

A `security.txt` should contain a `Canonical` field with a URL pointing to the canonical version of the `security.txt`. We should check if we retrieved the `security.txt` from the canonical URL and if not, do so.

### Program name

Currently, we use the input domain name as program name. This keeps output stable, but it may still differ from a canonical or redirected endpoint.
