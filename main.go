package main

import (
    "bufio"
    "flag"
    "fmt"
    "sync"
    "os"
    "net/http"
    "crypto/tls"
    "net"
    "time"
    "io/ioutil"
    "log"
    "strings"
)


func main() {
        concurrencyPtr := flag.Int("t", 8, "Number of threads to utilise. Default is 8.")
        flag.Parse()

        client := &http.Client{Transport: &http.Transport{
                TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
                Dial:                (&net.Dialer{Timeout: 0, KeepAlive: 0}).Dial,
                TLSHandshakeTimeout: 5 * time.Second,
        }}

        numWorkers := *concurrencyPtr
        work := make(chan string)
        go func() {
            s := bufio.NewScanner(os.Stdin)
            for s.Scan() {
                for _, schema := range []string{"http://","https://"}{
                    for _, location := range []string{"/.well-known/security.txt","/security.txt"}{
                        url := schema + s.Text() + location
                        work <- url 
                    }
                }
            }
            close(work)
        }()

        wg := &sync.WaitGroup{}

        for i := 0; i < numWorkers; i++ {
            wg.Add(1)
            go doWork(work, wg, client)
        }
        wg.Wait()
}

func doWork(work chan string, wg *sync.WaitGroup, client *http.Client) {
    defer wg.Done()
    for url := range work {
        defer wg.Done()
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
            log.Fatal(err)
        }
        resp, err := client.Do(req)
        if err != nil {
            log.Fatal(err)
        }
        bodyString := ""
        req.Header.Set("Connection", "close")
        if resp.StatusCode == http.StatusOK {
            bodyBytes, err := ioutil.ReadAll(resp.Body)
            if err != nil {
                log.Fatal(err)
            }
            bodyString = string(bodyBytes)
        }
        for _, signature := range []string{"Contact:", "Encryption:", "Acknowledgments:", "Preferred-Languages:", "Canonical:", "Policy:", "Hiring:"}{
            if strings.Contains(bodyString, signature){
                fmt.Print("\n\n###########################\nFOUND security.txt: " + url + "\n###########################\n")
                fmt.Print(bodyString)
            }
        }
        resp.Body.Close()
        //fmt.Println(resp.StatusCode, url)
    }
}
