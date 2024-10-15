# NFS
## NMAP
- `nmap 10.129.14.128 -p111,2049 -sVC`
- `nmap --script nfs* 10.129.14.128 -sV -p111,2049`

## NFS Shares

- `showmount -e 10.129.14.128` Show Available NFS Shares
- `sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock`
- `sudo umount target-NFS`