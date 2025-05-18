# diosts

The disclose.io security.txt scraper (`diosts`) takes a list of domains as the input, retrieves and validates the `security.txt` if available and outputs it in the disclose.io JSON format.

## Installation

### Prerequisites: 
- Go 1.13 or newer

### Option 1: Using go install (recommended)
```bash
# Install the latest version (v0.2.2)
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

The tool fully supports RFC 9116 compliance checking and will report:
- Whether a security.txt file is RFC compliant 
- Specific compliance issues found
- Expires date checking (required field per RFC 9116)
- Field validation according to the standard

## Notes

### Redirects

According to the specifications, a redirect should be followed when retrieving `security.txt`. However:

> When retrieving the file and any resources referenced in the file,
> researchers should record any redirects since they can lead to a
> different domain or IP address controlled by an attacker.  Further
> inspections of such redirects is recommended before using the
> information contained within the file.

At this point, we blindly accept redirects within the same organization (e.g., google.com to www.google.com is accepted). Any other redirect is logged as an error, to be dealt with later.

### Canonical

A `security.txt` should contain a `Canonical` field with a URL pointing to the canonical version of the `security.txt`. We should check if we retrieved the `security.txt` from the canonical URL and if not, do so.

### Program name

Currently, we use the input domain name as program name. This might or might not be correct, especially with redirects and canonical URL entries. To be discussed later.
