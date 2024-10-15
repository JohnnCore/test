# REVERSE DNS:
## dig:
- `dig @10.10.11.166 -x 10.10.11.166`
- `dig axfr friendzone.red @10.10.10.123`

`dig ns inlanefreight.htb @10.129.171.81`
`dig CH TXT version.bind 10.129.171.81`
`dig any inlanefreight.htb @10.129.171.81`
`dig axfr ns.inlanefreight.htb @10.129.171.81
`dig axfr internal.inlanefreight.htb @10.129.14.128`
`dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb`
