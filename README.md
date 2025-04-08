

EXAMPLE
***
```go
package main

import "github.com/trueHyper/rdp-scanner/scanner"
import "github.com/trueHyper/rdp-scanner/glog"
import "log"
import "os"
import "sync"

func main() {

	glog.SetLevel(glog.INFO)
	glog.SetLogger(log.New(os.Stdout, "", 0))
	
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
    /* RDPScann("ip:port", base64 compress %, bitmap timeout, screen H, screen W) */
		scanner.RDPScann("5.188.53.40:3389", 80, 2000, 640, 800)
	}()
	wg.Wait()
}
```

> В проект импортируем glog и scanner -> go mod tidy -> используем функцию scanner.RDPScann(...)
