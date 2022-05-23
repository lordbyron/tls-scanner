package scanners

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	nmap "github.com/tomsteele/go-nmap"
)

type NmapScanner struct {
	portStr string
}

func NewNmapScanner(portStr string) NmapScanner {
	return NmapScanner{
		portStr: portStr,
	}
}

func (s *NmapScanner) Scan(host string) ([]int, error) {
	cmd := exec.Command("nmap", host, "--open", "-oX", "-", "-Pn", "-p", s.portStr)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		e := err.(*exec.ExitError)
		fmt.Fprintf(os.Stderr, string(e.Stderr))
		return []int{}, err
	}

	nmaprun, err := nmap.Parse(out.Bytes())

	if len(nmaprun.Hosts) < 1 {
		fmt.Fprintf(os.Stderr, "No host found at %s\n", host)
		return []int{}, nil
	}
	ports := s.ports(nmaprun.Hosts[0])

	return ports, nil
}

func (s *NmapScanner) ports(host nmap.Host) []int {
	ports := []int{}
	for _, p := range host.Ports {
		ports = append(ports, p.PortId)
	}
	return ports
}
