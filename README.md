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


