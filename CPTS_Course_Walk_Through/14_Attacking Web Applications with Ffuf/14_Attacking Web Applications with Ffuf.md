# **Directory Fuzzing**

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 94.237.50.221:49766   

+ 0  In addition to the directory we found above, there is another directory that can be found. What is it?

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://94.237.50.221:49766/FUZZ
```

# **Page Fuzzing**

#### Questions
+ 1  Try to use what you learned in this section to fuzz the '/blog' directory and find all pages. One of them should contain a flag. What is the flag?

## Fuzzing extensions

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://94.237.50.221:49766/blog/indexFUZZ
```

## Fuzzing pages

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://94.237.50.221:49766/blog/FUZZ.php
```

Get flag

```zsh
curl http://94.237.50.221:49766/blog/home.php
```

# Recursive Fuzzing

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://94.237.50.221:49766/FUZZ -recursion -recursion-depth 1 -e .php -v
```

# Sub-domain Fuzzing

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Cheat Sheet

+ 0  Try running a sub-domain fuzzing test on 'inlanefreight.com' to find a customer sub-domain portal. What is the full domain of it?

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com -t 64
```

vhost fuzzing method
```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb:33431/ -H "Host: FUZZ.academy.htb"
```
# Parameter Fuzzing - GET

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s):  Target is spawning...  

Cheat Sheet

+ 0  Using what you learned in this section, run a parameter fuzzing scan on this page. What is the parameter accepted by this webpage?

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:45657/admin/admin.php?FUZZ=key -fs 798
```

# Parameter Fuzzing - POST

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:45657/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

# Value Fuzzing

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 94.237.59.174:45657   

Life Left: 71 minute(s)

Cheat Sheet

+ 1  Try to create the 'ids.txt' wordlist, identify the accepted value with a fuzzing scan, and then use it in a 'POST' request with 'curl' to collect the flag. What is the content of the flag?

```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

or python

```python
with open('ids.txt', 'w') as f:
    f.writelines(f"{i}\n" for i in range(1, 1001))
```

FUZZING and get flag

```zsh
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:45657/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 768
```

```zsh
curl http://admin.academy.htb:45657/admin/admin.php -X POST -d 'id=73' -H 'Content-Type: application/x-www-form-urlencoded'
```


# Skills Assessment - Web Fuzzing

---

You are given an online academy's IP address but have no further information about their website. As the first step of conducting a Penetration Test, you are expected to locate all pages and domains linked to their IP to enumerate the IP and domains properly.

Finally, you should do some fuzzing on pages you identify to see if any of them has any parameters that can be interacted with. If you do find active parameters, see if you can retrieve any data from them.

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 94.237.50.221:41187   

Life Left: 89 minute(s)

Cheat Sheet

+ 1  Run a sub-domain/vhost fuzzing scan on '*.academy.htb' for the IP shown above. What are all the sub-domains you can identify? (Only write the sub-domain name)

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://academy.htb:41187/ -H "Host: FUZZ.academy.htb" -fs 985
```

+ 1  Before you run your page fuzzing scan, you should first run an extension fuzzing scan. What are the different extensions accepted by the domains?

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://archive.academy.htb:41187/indexFUZZ
```

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://faculty.academy.htb:41187/indexFUZZ
```

`php, phps, php7`

+ 2  One of the pages you will identify should say 'You don't have access!'. What is the full page URL?

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://faculty.academy.htb:41187/FUZZ -recursion -recursion-depth 1 -e .php7,.phps,.php -v -fs 287,0
```

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://faculty.academy.htb:41187/courses/FUZZ -e .php7,.phps,.php -fs 287,0
```

+ 1  In the page from the previous question, you should be able to find multiple parameters that are accepted by the page. What are they?

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:41187/courses/linux-security.php7?FUZZ=key -fs 774
```

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:41187/courses/linux-security.php7 -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 774
```

+ 2  Try fuzzing the parameters you identified for working values. One of them should return a flag. What is the content of the flag?

```zsh
ffuf -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ -u http://faculty.academy.htb:41187/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 781
```

```zsh
curl -X POST http://faculty.academy.htb:41187/courses/linux-security.php7 -d 'username=harry' -H 'Content-Type: application/x-www-form-urlencoded'  
<div class='center'><p>HTB{w3b_fuzz1n6_m4573r}</p></div>
```