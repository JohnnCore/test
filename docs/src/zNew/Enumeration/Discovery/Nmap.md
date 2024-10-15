## delete


# Nmap:
```bash 
$ nmap -sC -sV -script vuln <IP>`
$ nmap <IP> -p-`
$ nmap <IP> -p <PORT/S>`
$ nmap -sU 10.10.10.10`

$ nmap -T4 -p- -v <IP>
$ nmap -T4 -p <PORT/S> -A -sCV -v <IP>
```

    - `-sC` for the default scripts
    - `-sV` for Version and OS Enumeration
    - `-sU` UDP port scan
    - `-sn`	Disables port scanning
    - `-script vuln` Check for vulnerabilities using the Nmap scripting engine
    - `-p-` Port scan all ports
    - `-p` Port scan for port x
    - `-v` Increase the verbosity level (use -vv or more for greater effect)

## Host Scan 
| Scanning Options   | Description                                    |
|--------------------|------------------------------------------------|
| 10.129.2.28        | Scans the specified target.                   |
| -Pn                | Disables ICMP Echo requests.                   |
| -O                 | Performs operating system detection scan.                 |
| -sn                | Disables port scanning. | 
| -PE                | Performs the ping scan by using 'ICMP Echo requests' against the target. |
| --disable-arp-ping | Disables ARP ping.                             |
| --packet-trace     | Shows all packets sent and received.          |
| --reason           | Displays the reason a port is in a particular state. |

## Port Scanning
| Scanning Options   | Description                                    |
|--------------------|------------------------------------------------|
| -p-                | Scans all ports.                              |
| -p 137             | Scans only the specified port.                |
| -sV                | Performs service version detection on specified ports. |
| -sC	| Perform a Script Scan with scripts that are categorized as "default". |
| -F                 | Scans top 100 ports.         |
| -sU                | Performs a UDP scan.         |
| --top-ports=<num>  | Scans the specified top ports that have been defined as most frequent. | 

## Tunning
| Scanning Options   | Description                                    |
|--------------------|------------------------------------------------|
| -v	| Increases the verbosity of the scan, which displays more detailed information. |
| -A                 | Performs service detection, OS detection, traceroute, and uses default scripts to scan the target. |
| -T <0-5>               | Specifies the insane timing template.  |
| --script <script,> | Uses specified NSE scripts.  |
| --initial-rtt-timeout 50ms | Sets the specified time value as initial RTT timeout. |
| --max-rtt-timeout 100ms   | Sets the specified time value as maximum RTT timeout.  |
| --max-retries 0    | Sets the number of retries that will be performed during the scan. |
| --min-parallelism <number> | which frequency |
| --min-rate 300     | Sets the minimum number of packets to be sent per second.         |
| -n                 | Disables DNS resolution.                       |

## Evasion 
| Scanning Options   | Description                                    |
|--------------------|------------------------------------------------|
| -sS	| Performs SYN scan on specified ports. |
| -sA	| Performs ACK scan on specified ports |
| -S                 | Scans the target using different source IP addresses.    |
| -D RND:5	| Generates five random IP addresses that indicates the source IP the connection comes from. |
| --source-port 53	| Performs the scans from specified source port. |

## Save the result
| Scanning Options   | Description                                    |
|--------------------|------------------------------------------------|
| -oA target         | Saves the results in all formats, starting the name of each file with 'target'. |

## Host Discovery
### Scan Network Range
```bash
$ sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

### Scan IP List
```bash
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```

### Scan Multiple IPs
```bash
$ sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5
```

## Discovering Open UDP Ports
```bash
$ sudo nmap 10.129.2.28 -F -sU
```

## Different Formats
`sudo nmap 10.129.2.28 -p- -oA target`

## 
```bash
$ sudo nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```