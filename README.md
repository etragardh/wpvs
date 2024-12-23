# wpvs
WordPress Vulnerability Scanner

```
./wpvs
./wpvs --age 10 (10 days old or newer)
./wpvs --cvss-min 9 --age 5 --type RCE
./wpvs --debug
```


First run takes some time since a lot of requests is sent. Everything is cached and searches are 100% local if possible.<br />
<br />
+TODO: wp.org rate limit detection does not work at the moment.<br />
+TODO: add patchstack.com as a source.
