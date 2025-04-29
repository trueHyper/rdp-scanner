package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"net"
	"os"
	"log"
	"github.com/trueHyper/rdp-scanner/scanner"
	"github.com/trueHyper/rdp-scanner/glog"
)

func main() {
	glog.SetLevel(glog.INFO)
	glog.SetLogger(log.New(os.Stdout, "", 0))

	host := flag.String("host", "", "Usage <addr>:<port> (this field is required)")

	compress := flag.Int("c", 80, "Image compression percent: from 0 to 100")
	timeout := flag.Int("t", 2500, "Bitmap timeout in milliseconds, recommended >= 2500ms")
	height := flag.Int("h", 640, "Screen height in pixels")
	width := flag.Int("w", 800, "Screen width in pixels")

	flag.Parse()
	
	if err := validateHost(*host); err!=nil { 
		log.Fatal(err)
	}
	
	if *compress <= 0 { *compress = 1 }
	if *compress > 100 { *compress = 100 }
	if *timeout < 0 { *timeout = 2500 }
	if *height < 0 { *height = 640 }
	if *width < 0 { *width = 800 }

	scanner.RDPScann(
		*host,
		*compress,
		*timeout,
		*height,
		*width,
	)
}

func validateHost(host string) error {
	if host == "" {
		log.Fatal("Host is a required flag")
	}
	
	parts := strings.Split(host, ":")
	if len(parts) != 2 {
		return fmt.Errorf("Invalid format, must be ip:port")
	}

	ip := net.ParseIP(parts[0])
	if ip == nil {
		return fmt.Errorf("Invalid IP address")
	}

	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("The port must be a number")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("The port should be in the range 1-65535")
	}

	return nil
}
