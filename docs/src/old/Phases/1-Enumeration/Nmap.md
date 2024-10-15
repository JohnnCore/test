# Nmap:
- `nmap -sC -sV -script vuln 10.10.10.10`
- `nmap 10.10.10.10 -p-`
- `nmap 10.10.10.10 -p 80`
- `nmap -sU 10.10.10.10`

```
nmap -T4 -p- -v 10.10.10.10
nmap -T4 -p 80,443,743-749 -A -sCV -v 10.10.10.10
```

    - `-sC` for the default scripts
    - `-sV` for Version and OS Enumeration
    - `-sU` UDP port scan
    - `-script vuln` Check for vulnerabilities using the Nmap scripting engine
    - `-p-` Port scan all ports
    - `-p` Port scan for port x
    - `-v` Increase the verbosity level (use -vv or more for greater effect)

| Scanning Options   | Description                                    |
|--------------------|------------------------------------------------|
| 10.129.2.28        | Scans the specified target.                   |
| -p-                | Scans all ports.                              |
| -sV                | Performs service version detection on specified ports. |
| -A                 | Performs service detection, OS detection, traceroute, and uses default scripts to scan the target. |
| -Pn                | Disables ICMP Echo requests.                   |
| -sU                | Performs a UDP scan.         |
| -p 137             | Scans only the specified port.                |
| -n                 | Disables DNS resolution.                       |
| -O                 | Performs operating system detection scan.                 |
| -S                 | Scans the target using different source IP addresses.    |
| --disable-arp-ping | Disables ARP ping.                             |
| --packet-trace     | Shows all packets sent and received.          |
| -oA target         | Saves the results in all formats, starting the name of each file with 'target'. |
| -F                 | Scans top 100 ports.         |
| --reason           | Displays the reason a port is in a particular state. |
| -PE                | Performs the ping scan by using 'ICMP Echo requests' against the target. |
| --script banner,smtp-commands| Uses specified NSE scripts.                     |
| --initial-rtt-timeout 50ms | Sets the specified time value as initial RTT timeout. |
| --max-rtt-timeout 100ms   | Sets the specified time value as maximum RTT timeout.  |
| --max-retries 0    | Sets the number of retries that will be performed during the scan. |
| --min-rate 300     | Sets the minimum number of packets to be sent per second.         |
| -T 5               | Specifies the insane timing template.                          |
## Host Discovery
`sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5`

## Scan IP List
`sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5`

## Discovering Open UDP Ports
`sudo nmap 10.129.2.28 -F -sU`

## Different Formats
`sudo nmap 10.129.2.28 -p- -oA target`