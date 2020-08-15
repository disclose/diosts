# securitytxt-scraper

The disclose.io security.txt scraper (`diosts`) takes a list of domains as the input, retrieves and validates the `security.txt` if available and outputs it in the disclose.io JSON format.

# Installation
Prerequisites: a working Golang installation >= 1.13

```
go get github.com/disclose/securitytxt-scraper
```

# Usage
```
cat domains.txt | ~/go/bin/diosts -t <threads> 2>diosts.log >securitytxt.json
```

This wil try and scrape the `security.txt` from the domains listed in `domains.txt`, with `<threads>` parallel threads (defaults to 8). Logging (with information on each of the domains in the input) will be written to `diosts.log` (because it's output to `stderr`) and a JSON array of retrieved `security.txt` information in disclose.io format will be written to `securitytxt.json`.

For each input, the following URIs are tried, in order:
1. `https://<domain>/.well-known/security.txt`
2. `https://<domain>/security.txt`
3. `http://<domain>/.well-known/security.txt`
4. `http://<domain>/security.txt`

Any non-fatal violations of the [`security.txt` specification](https://tools.ietf.org/html/draft-foudil-securitytxt-09) will be logged.

# Build
Note: building is not necessary if you use the installation instructions, Go will take care of this for you.

```
git clone https://github.com/disclose/securitytxt-scraper
cd securitytxt-scraper
go build ./cmd/diosts
```

# Notes

## Redirects

According to the specifications, a redirect should be followed when retrieving `security.txt`. However:

> When retrieving the file and any resources referenced in the file,
> researchers should record any redirects since they can lead to a
> different domain or IP address controlled by an attacker.  Further
> inspections of such redirects is recommended before using the
> information contained within the file.

At this point, we blindly accept redirects within the same organization (e.g., google.com to www.google.com is accepted). Any other redirect is logged as an error, to be dealt with later.

## Canonical

A `security.txt` should contain a `Canonical` field with a URL pointing to the canoncial version of the `security.txt`. We should check if we retrieved the `security.txt` from the canoncial URL and if not, do so.

## Program name

Currently, we use the input domain name as program name. This might or might not be correct, especially with redirects and canonical URL entries. To be discussed later.
