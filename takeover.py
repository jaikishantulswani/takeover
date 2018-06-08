#!/usr/bin/env python 
#
# TakeOver - Detect Potential Takeover Attacks
# Coded by Momo Outaadi (m4ll0k)

import re
import os
import sys
import time
import getopt
import urllib3
import urlparse
import requests

# -- common services
# -- Add new services
# -- {'NAME SERVICE' : {'code':'[300-499]','error':'ERROR HERE'}}
# -- https://github.com/EdOverflow/can-i-take-over-xyz

services = {
	'AWS/S3'     : {'code':'[300-499]','error':r'The specified bucket does not exit'},
	'BitBucket'  : {'code':'[300-499]','error':r'Repository not found'},
	'CloudFront' : {'code':'[300-499]','error':r'ERROR\: The request could not be satisfied'},
	'Github'     : {'code':'[300-499]','error':r'There isn\'t a Github Pages site here\.'},
	'Shopify'    : {'code':'[300-499]','error':r'Sorry\, this shop is currently unavailable\.'},
	'Desk'       : {'code':'[300-499]','error':r'Sorry\, We Couldn\'t Find That Page'},
	'Fastly'     : {'code':'[300-499]','error':r'Fastly error\: unknown domain\:'},
	'FeedPress'  : {'code':'[300-499]','error':r'The feed has not been found\.'},
	'Ghost'      : {'code':'[300-499]','error':r'The thing you were looking for is no longer here\, or never was'},
}

# -- colors 
r ='\033[1;31m'
g ='\033[1;32m'
y ='\033[1;33m'
b ='\033[1;34m'
r_='\033[0;31m'
g_='\033[0;32m'
y_='\033[0;33m'
b_='\033[0;34m'
e_='\033[0m'

# -- print
def plus(string):
	print("{}[+]{} {}{}{}".format(g,e_,g_,string,e_))

def warn(string):
	print("{}[!]{} {}{}{}".format(r,e_,r_,string,e_))

def info(string):
	print("{}[i]{} {}{}{}".format(y,e_,y_,string,e_))

def request(url,proxy):
	headers = {'User-Agent':'Mozilla/5.0'}
	try:
		req = requests.packages.urllib3.disable_warnings(
			urllib3.exceptions.InsecureRequestWarning
			)
		if proxy:
			req = requests.get(url=url,headers=headers,proxies=proxy)
		else:
			req = requests.get(url=url,headers=headers)
		return req.status_code,req.content
	except Exception as e:
		warn('%s'%e.message)
	return None,None

def checker(status,content):
	code = ""
	error = ""
	# --
	for service in services:
		values = services[service]
		for value in values:
			opt = services[service][value]
			if value == 'error':error = opt 
			if value == 'code':code = opt 
		# ---
		if re.search(code,str(status),re.I) and re.search(error,str(content),re.I):
			return service,error
	return None,None

def banner():
	print "                            "
	print "   /~\\                     "
	print "  C oo   ---------------    "
 	print " _( ^)  |T|A|K|E|O|V|E|R|   "
	print "/   ~\\  ----------------   "
	print "#> by Momo Outaadi (m4ll0k) "
	print "#> http://github.com/m4ll0k "
	print "-"*40

def help():
	banner()
	print "Usage: takeover.py [OPTIONS]\n"
	print "\t-s --sub-domain\t\tSet sub-domain URL (e.g: admin.example.com)"
	print "\t-l --sub-domain-list\tScan multiple targets in a text file"
	print "\t-p --set-proxy\t\tUse a proxy to connect to the target URL\n"
	sys.exit()

def sett_proxy(proxy):
	info('Setting proxy.. %s'%proxy)
	return {
	'http':proxy,
	'https':proxy,
	'ftp':proxy
	}

def check_path(path):
	try:
		if os.path.exists(path):
			return path
	except Exception as e:
		warn('%s'%e.message)
		sys.exit()

def readfile(path):
	info('Read wordlist.. %s'%(path))
	try:
		return [l.strip() for l in open(check_path(path),'rb')]
	except Exception as e:
		warn('%s'%e.message)
		sys.exit()

def check_url(url):
	o = urlparse.urlsplit(url)
	if o.scheme not in ['http','https','']:
		warn('Scheme %s not supported!!'%(o.scheme))
		sys.exit()
	if o.netloc == '':
		return 'http://'+o.path
	elif o.netloc:
		return o.scheme + '://' + o.netloc
	else:
		return 'http://' + o.netloc

def main():
	# ---
	set_proxy = None
	sub_domain = None
	sub_domain_list = None
	# ---
	if len(sys.argv) < 2: help()
	try:
		opts,args = getopt.getopt(sys.argv[1:],'s:l:p:',
			['sub-domain=','sub-domain-list=','set-proxy='])
	except Exception as e:
		warn("%s"%e.message)
		time.sleep(1)
		help()
	banner()
	for o,a in opts:
		if o in ('-s','--sub-domain'):sub_domain = check_url(a)
		if o in ('-l','--sub-domain-list'):sub_domain_list = readfile(a)
		if o in ('-p','--set-proxy'):set_proxy = sett_proxy(a)
	# ---
	if sub_domain:
		plus('Starting scanning...')
		info('Target url... %s'%sub_domain)
		status,content = request(sub_domain,set_proxy)
		service,error = checker(status,content)
		if service and error:
			plus('Found service: %s'%service)
			plus('A potential TAKEOVER vulnerability found!')
	elif sub_domain_list:
		plus('Starting scanning...')
		for sub_domain in sub_domain_list:
			sub_domain = check_url(sub_domain)
			info('Target url... %s'%sub_domain)
			status,content = request(sub_domain,set_proxy)
			service,error = checker(status,content)
			if service and error:
				plus('Found service \"%s\" -> %s'%(service,sub_domain))
				plus('A potential TAKEOVER vulnerability found!')
	else:help()
try:
	main()
except KeyboardInterrupt as e:
	warn('Interrupt by user!')
	sys.exit()