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
