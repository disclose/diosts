package main 
import (
        "bufio"
        "strings"
        "crypto/tls"
        "fmt"
        "log"
        "net"
        "net/http"
        "io/ioutil"
        "os"
        "sync"
        "syscall"
        "time"
)

func ulimit() (uint64, error) {
        var rLimit syscall.Rlimit
        err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
        if err != nil {
                return 0, err
        }
        return rLimit.Cur, nil
}

func main() {
        maxFileDescriptors, err := ulimit()
        if err != nil {
                log.Fatal(err)
        }
        if maxFileDescriptors-100 < 0 {
                log.Fatalf("maxFileDescriptors==%d is not enough", maxFileDescriptors)
        }

        var wg sync.WaitGroup
        lock := make(chan struct{}, maxFileDescriptors-100)
        client := &http.Client{Transport: &http.Transport{
                TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
                Dial:                (&net.Dialer{Timeout: 0, KeepAlive: 0}).Dial,
                TLSHandshakeTimeout: 5 * time.Second,
        }}

        scanner := bufio.NewScanner(os.Stdin)
        for scanner.Scan() {
            for _, schema := range []string{"http://","https://"}{
                for _, location := range []string{"/.well-known/security.txt","/security.txt"}{
                    url := schema + scanner.Text() + location
                    wg.Add(1)
                    lock <- struct{}{}
                    go func(url string) {
                            defer wg.Done()
                            defer func() { <-lock }()

                            req, err := http.NewRequest("GET", url, nil)
                            if err != nil {
                                log.Fatal(err)
                            }
                            resp, err := client.Do(req)
                            if err != nil {
                                    //fmt.Println(999, err, url)
                                    return
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
                                return
                            }
                            resp.Body.Close()
                            fmt.Println(resp.StatusCode, url)
                    }(url)
                }
            }
        }
        if err := scanner.Err(); err != nil {
                fmt.Println(err)
        }
        wg.Wait()
}
