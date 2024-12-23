# wpvs
WordPress Vulnerability Scanner

First run takes some time since a lot of requests is sent. Everything is cached and searches are 100% local if possible.<br />
<br />
This tool is for searching vulnerability datebases. Not for scanning a website.

## Installation
```
git clone https://github.com/etragardh/wpvs.git
cd wpvs
pip freeze > requirements.txt
pip install -r requirements.txt
```

## Usage
```
./wpvs
./wpvs --age 10 (10 days old or newer)
./wpvs --cvss-min 9 --age 5 --type RCE
./wpvs --debug
```

## Vulnerability Sources
+ wordfence.com (vulnerability api)
+ patchstack.com (web crawler)
+ wordpress.org (installations, downloads etc)

## TODO
+ Add support for cve-info
+ rewrite with sqlite database
+ lift out some heavy loading from sources/mysource.py to source.py
+ add info about firewalls (ie v-patch exists, WF firewall rule free/premium)
+ add codecanyon as a source

<br />
Stay nice!
