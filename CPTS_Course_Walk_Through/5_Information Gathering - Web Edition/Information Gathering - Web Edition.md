# Utilising WHOIS

1. Perform a WHOIS lookup against the paypal.com domain. What is the registrar Internet Assigned Numbers Authority (IANA) ID number? -> 292
```zsh
❯ whois paypal.com
   Domain Name: PAYPAL.COM
   Registry Domain ID: 8017040_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.markmonitor.com
   Registrar URL: http://www.markmonitor.com
   Updated Date: 2024-10-08T21:00:07Z
   Creation Date: 1999-07-15T05:32:11Z
   Registry Expiry Date: 2025-07-15T05:32:11Z
   Registrar: MarkMonitor Inc.
   Registrar IANA ID: 292
   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
   Registrar Abuse Contact Phone: +1.2086851750
```
2. What is the admin email contact for the tesla.com domain (also in-scope for the Tesla bug bounty program)? -> admin@dnstinations.com
```zsh
❯ whois tesla.com
Registry Admin ID: 
Admin Name: Domain Administrator
Admin Organization: DNStination Inc.
Admin Street: 3450 Sacramento Street, Suite 405
Admin City: San Francisco
Admin State/Province: CA
Admin Postal Code: 94118
Admin Country: US
Admin Phone: +1.4155319335
Admin Phone Ext: 
Admin Fax: +1.4155319336
Admin Fax Ext: 
Admin Email: admin@dnstinations.com
```

# Digging DNS

1. Which IP address maps to inlanefreight.com? -> 134.209.24.248
```zsh
❯ host inlanefreight.com
inlanefreight.com has address 134.209.24.248
inlanefreight.com has IPv6 address 2a03:b0c0:1:e0::32c:b001
inlanefreight.com mail is handled by 10 mail1.inlanefreight.com.
```
2.  Which domain is returned when querying the PTR record for 134.209.24.248?
```zsh
❯ dig -x 134.209.24.248 +short
inlanefreight.com.
```
3. What is the full domain returned when you query the mail records for facebook.com?
```zsh
❯ dig MX facebook.com +short
10 smtpin.vvv.facebook.com.
```

# Subdomain Bruteforcing

1. Using the known subdomains for inlanefreight.com (www, ns1, ns2, ns3, blog, support, customer), find any missing subdomains by brute-forcing possible domain names. Provide your answer with the complete subdomain, e.g., www.inlanefreight.com -> my.inlanefreight.com
```zsh
❯ dnsenum --enum inlanefreight.com -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
www.inlanefreight.com.                   300      IN    A        134.209.24.248                                                                              
ns1.inlanefreight.com.                   282      IN    A        178.128.39.165
ns2.inlanefreight.com.                   300      IN    A        206.189.119.186
blog.inlanefreight.com.                  300      IN    A        134.209.24.248
ns3.inlanefreight.com.                   300      IN    A        134.209.24.248
support.inlanefreight.com.               300      IN    A        134.209.24.248
my.inlanefreight.com.                    300      IN    A        134.209.24.248
```

# DNS Zone Transfers

+ .After performing a zone transfer for the domain inlanefreight.htb on the target system, how many DNS records are retrieved from the target system's name server? Provide your answer as an integer, e.g, 123.
```zsh
❯ dig axfr inlanefreight.htb @10.129.30.154 +short | wc -l
22
```
+ Within the zone record transferred above, find the ip address for ftp.admin.inlanefreight.htb. Respond only with the IP address, eg 127.0.0.1
```zsh
❯ dig axfr inlanefreight.htb @10.129.30.154 | awk '{sub(/\.$/, "", $1); print $5, $1}' | grep "ftp"
10.10.34.2 ftp.admin.inlanefreight.htb
```
+ Within the same zone record, identify the largest IP address allocated within the 10.10.200 IP range. Respond with the full IP address, eg 10.10.200.1
```zsh
❯ dig axfr inlanefreight.htb @10.129.30.154 +short | grep "10.10.200"
10.10.200.5
10.10.200.14
10.10.200.10
```

# Virtual Hosts

```zsh
echo "94.237.63.28:51992   inlanefreight.htb" | sudo tee -a /etc/hosts
❯ gobuster vhost -u http://inlanefreight.htb:51992/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 50 --timeout=5s
Found: admin.inlanefreight.htb:51992 Status: 200 [Size: 100]
Found: support.inlanefreight.htb:51992 Status: 200 [Size: 104]
Found: forum.inlanefreight.htb:51992 Status: 200 [Size: 100]
Found: blog.inlanefreight.htb:51992 Status: 200 [Size: 98]
Found: vm5.inlanefreight.htb:51992 Status: 200 [Size: 96]
Found: browse.inlanefreight.htb:51992 Status: 200 [Size: 102]
Found: web17611.inlanefreight.htb:51992 Status: 200 [Size: 106]
```

+ Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "web"? Answer using the full domain, e.g. "x.inlanefreight.htb" **`web17611.inlanefreight.htb`**

+  Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "vm"? Answer using the full domain, e.g. "x.inlanefreight.htb" -> **vm5.inlanefreight.htb**

+ Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "br"? Answer using the full domain, e.g. "x.inlanefreight.htb" -> **`browse.inlanefreight.htb`**

+  Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "a"? Answer using the full domain, e.g. "x.inlanefreight.htb" -> **`admin.inlanefreight.htb`**

+ Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "su"? Answer using the full domain, e.g. "x.inlanefreight.htb" -> **support.inlanefreight.htb**

# Fingerprinting

Target(s): 10.129.98.87 (ACADEMY-ATCKAPPS-APP01)   
vHosts needed for these questions:

- `app.inlanefreight.local`
- `dev.inlanefreight.local`

- Determine the Apache version running on app.inlanefreight.local on the target system. (Format: 0.0.0)

```zsh
❯ curl -I http://app.inlanefreight.local
HTTP/1.1 200 OK
Date: Thu, 03 Apr 2025 13:50:04 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: 72af8f2b24261272e581a49f5c56de40=o3hho9369hken0hi87v6ejggtv; path=/; HttpOnly
Permissions-Policy: interest-cohort=()
Expires: Wed, 17 Aug 2005 00:00:00 GMT
Last-Modified: Thu, 03 Apr 2025 13:50:04 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Content-Type: text/html; charset=utf-8
```

- Which CMS is used on app.inlanefreight.local on the target system? Respond with the name only, e.g., WordPress.

```zsh
❯ droopescan scan -u app.inlanefreight.local
[+] Site identified as joomla.
[+] Possible version(s):                                                        
    3.10.0-alpha1

[+] Possible interesting urls found:
    Detailed version information. - http://app.inlanefreight.local/administrator/manifests/files/joomla.xml
    Login page. - http://app.inlanefreight.local/administrator/
    License file. - http://app.inlanefreight.local/LICENSE.txt
    Version attribute contains approx version - http://app.inlanefreight.local/plugins/system/cache/cache.xml
```

- On which operating system is the dev.inlanefreight.local webserver running in the target system? Respond with the name only, e.g., Debian.

```zsh
❯ curl -I http://dev.inlanefreight.local
HTTP/1.1 200 OK
Date: Thu, 03 Apr 2025 13:49:34 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: 02a93f6429c54209e06c64b77be2180d=9d12tgvq1ch3keqf3ubs37rt6b; path=/; HttpOnly
Expires: Wed, 17 Aug 2005 00:00:00 GMT
Last-Modified: Thu, 03 Apr 2025 13:49:42 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Content-Type: text/html; charset=utf-8
```