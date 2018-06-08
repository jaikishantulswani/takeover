# TakeOver

![screen](https://raw.githubusercontent.com/m4ll0k/takeover/master/screen.png)

Sub-domain takeover vulnerability occur when a sub-domain (__subdomain.example.com__) is pointing to a service (e.g: __GitHub__, __AWS/S3__,..) that has been removed or deleted. This allows an attacker to set up a page on the service that was being used and point their page to that sub-domain. For example, if __subdomain.example.com__ was pointing to a GitHub page and the user decided to delete their GitHub page, an attacker can now create a GitHub page, add a __CNAME__ file containing __subdomain.example.com__, and claim __subdomain.example.com__. For more information: [here](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/)

## Installation:

```
# git clone https://github.com/m4ll0k/takeover.git
# cd takeover
# python takeover.py
```
__or:__

```
wget -q https://raw.githubusercontent.com/m4ll0k/takeover/master/takeover.py && python takeover.py
```
