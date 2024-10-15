## delete


# Footprinting
```bash
# SNMPwalk
$ snmpwalk -v2c -c public <IP>

# OneSixtyOne
$ sudo apt install onesixtyone
$ onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt <IP>

"""
Once we know a community string, we can use it with braa to brute-force the individual OIDs and enumerate the information behind them.
"""

# Braa
$ sudo apt install braa
$ braa <community strings>@<IP>:.1.3.6.*
```