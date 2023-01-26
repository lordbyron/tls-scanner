package scanners

import (
	"crypto/tls"
	"fmt"
	"os"
)

type TLSVersionScanner struct {
	vers    int
	versStr string
}

func NewTLSVersionScanner(vers string) TLSVersionScanner {
	var v int
	switch vers {
	case "ssl3":
		v = tls.VersionSSL30
	case "tls1":
		v = tls.VersionTLS10
	case "tls1_1":
		v = tls.VersionTLS11
	case "tls1_2":
		v = tls.VersionTLS12
	case "tls1_3":
		v = tls.VersionTLS13
	default:
		panic("tls version not recognized")
	}
	return TLSVersionScanner{
		vers:    v,
		versStr: vers,
	}
}

func (s TLSVersionScanner) Scan(host string, port int) (bool, error) {
	connStr := host + ":" + fmt.Sprint(port)
	fmt.Printf("Testing %s %s\n", connStr, s.versStr)
	_, err := tls.Dial("tcp", connStr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         uint16(s.vers),
		MaxVersion:         uint16(s.vers),
	})
	if err == nil {
		return true, nil
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", connStr, err.Error())
	return false, nil
}
