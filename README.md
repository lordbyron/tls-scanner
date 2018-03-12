# tls-scanner

```
Usage: ./bin/tls-scanner [-f hostsfile | -h host] <checks>

  -h, --host string        Test a single host
  -f, --hostsfile string   File that contains list of hostnames or IPs
  -p, --port string        Ports to scan (default "1-1000,8000-8999")
      --ssl3               Test if host supports SSL 3
      --tls1               Test if host supports TLS 1.0
      --tls1_1             Test if host supports TLS 1.1
      --tls1_2             Test if host supports TLS 1.2
```
