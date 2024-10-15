## Vhosts
### vHost Fuzzing
`cat ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://192.168.10.10 -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done`

`curl -s http://192.168.10.10 -H "Host: dev-admin.randomtarget.com"`

### Automating Virtual Hosts Discovery
`ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612`

where:

    -w: Path to our wordlist
    -u: URL we want to fuzz
    -H "HOST: FUZZ.randomtarget.com": This is the HOST Header, and the word FUZZ will be used as the fuzzing point.
    -fs 612: Filter responses with a size of 612, default response size in this case.


## Crawling
### FFuF
`ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt`


```
cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10
```
    -w: We separate the wordlists by coma and add an alias to them to inject them as fuzzing points later
    -u: Our target URL with the fuzzing points.


`ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS`


