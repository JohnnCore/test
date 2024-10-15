## delete


# Footprinting
## Nmap
```bash
$ nmap <IP> -p111,2049 -sVC
$ nmap --script nfs* <IP> -sV -p111,2049
```

# NFS Shares
## Show Available NFS Shares
```bash
$ showmount -e <IP> 
```

## Mounting NFS Share
```bash
$ mkdir target-NFS
$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
$ cd target-NFS
$ tree .
```

## Unmounting
```bash
$ sudo umount target-NFS
```