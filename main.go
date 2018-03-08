package main

import (
	"encoding/csv"
	"fmt"
	"github.com/lordbyron/tls-scanner/scanners"
	"github.com/spf13/pflag"
	"io/ioutil"
	"os"
	"strings"
)

const (
	portsDefault = "1-1000,8000-8999"
)

var hostsfile string
var host string
var checkSSL3 bool
var checkTLS1 bool
var checkTLS11 bool
var checkTLS12 bool
var portStr string

func init() {
	pflag.StringVarP(&hostsfile, "hostsfile", "f", "", "File that contains list of hostnames or IPs")
	pflag.StringVarP(&host, "host", "h", "", "Test a single host")
	pflag.StringVarP(&portStr, "port", "p", portsDefault, "Ports to scan")
	pflag.BoolVarP(&checkSSL3, "ssl3", "", false, "Test if host supports SSL 3")
	pflag.BoolVarP(&checkTLS1, "tls1", "", false, "Test if host supports TLS 1.0")
	pflag.BoolVarP(&checkTLS11, "tls1_1", "", false, "Test if host supports TLS 1.1")
	pflag.BoolVarP(&checkTLS12, "tls1_2", "", false, "Test if host supports TLS 1.2")
	pflag.Parse()

	if host == "" && hostsfile == "" || host != "" && hostsfile != "" {
		fmt.Fprintf(os.Stderr, "Usage: %s [-f hostsfile | -h host] <checks>\n\n", os.Args[0])
		pflag.PrintDefaults()
		os.Exit(1)
	}
}

func main() {
	var hosts []string
	if hostsfile != "" {
		dat, err := ioutil.ReadFile(hostsfile)
		if err != nil {
			panic(err)
		}
		hosts = strings.Fields(string(dat))
	} else {
		hosts = []string{host}
	}

	nms := scanners.NewNmapScanner(portStr)
	header, scans := makeScanners()
	writer := csv.NewWriter(os.Stdout)
	header = append([]string{"host", "port"}, header...)
	writer.Write(header)

	for _, h := range hosts {
		ports, err := nms.Scan(h)
		if err != nil {
			panic(err)
		}
		if len(ports) == 0 {
			r := []string{h, "down"}
			writer.Write(r)
			continue
		}
		for _, p := range ports {
			r := []string{h, fmt.Sprint(p)}
			for _, s := range scans {
				support, _ := s.Scan(h, p)
				r = append(r, fmt.Sprint(support))
			}
			writer.Write(r)
			writer.Flush()
		}
	}
	writer.Flush()
}

func makeScanners() (header []string, scans []scanners.Scanner) {
	if checkSSL3 {
		header = append(header, "ssl3")
		scans = append(scans, scanners.NewTLSVersionScanner("ssl3"))
	}
	if checkTLS1 {
		header = append(header, "tls1")
		scans = append(scans, scanners.NewTLSVersionScanner("tls1"))
	}
	if checkTLS11 {
		header = append(header, "tls1_1")
		scans = append(scans, scanners.NewTLSVersionScanner("tls1_1"))
	}
	if checkTLS12 {
		header = append(header, "tls1_2")
		scans = append(scans, scanners.NewTLSVersionScanner("tls1_2"))
	}
	return
}
