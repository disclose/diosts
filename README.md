# haksecuritytxt
Takes a list of domains as the input, checks if they have a security.txt, outputs the results.

# installation
```
go get github.com/hakluke/haksecuritytxt
```

# usage
```
cat domains.txt | ~/go/bin/haksecuritytxt -t <threads>
```
Default number of threads is 8.

# build
Note: building is not necessary if you use the installation instructions, it will do it for you.
```
git clone https://github.com/hakluke/haksecuritytxt
cd haksecuritytxt
go build *.go
```

# Notes

## Redirects

According to the specifications, a redirect should be followed when retrieving `security.txt`. However:

   When retrieving the file and any resources referenced in the file,
   researchers should record any redirects since they can lead to a
   different domain or IP address controlled by an attacker.  Further
   inspections of such redirects is recommended before using the
   information contained within the file.

At this point, we blindly accept redirects within the same organization (e.g., google.com to www.google.com is accepted). Any other redirect is logged as an error, to be dealt with later.

## Canonical

A `security.txt` should contain a `Canonical` field with a URL pointing to the canoncial version of the `security.txt`. We should check if we retrieved the `security.txt` from the canoncial URL and if not, do so.

## Program name

Currently, we use the input domain name as program name. This might or might not be correct, especially with redirects and canonical URL entries. To be discussed later.
