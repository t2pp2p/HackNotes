# The Networking Behind Pivoting

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Cheat Sheet

+ 1  Reference the Using ifconfig output in the section reading. Which NIC is assigned a public IP address?

 ```zsh
0xsrt@htb[/htb]$ ifconfig

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 134.122.100.200  netmask 255.255.240.0  broadcast 134.122.111.255
        inet6 fe80::e973:b08d:7bdf:dc67  prefixlen 64  scopeid 0x20<link>
        ether 12:ed:13:35:68:f5  txqueuelen 1000  (Ethernet)
        RX packets 8844  bytes 803773 (784.9 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5698  bytes 9713896 (9.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
+ 1  Reference the Routing Table on Pwnbox output shown in the section reading. If a packet is destined for a host with the IP address of 10.129.10.25, out of which NIC will the packet be forwarded?

tun0
+ 1  Reference the Routing Table on Pwnbox output shown in the section reading. If a packet is destined for www.hackthebox.com what is the IP address of the gateway it will be sent to?
178.62.64.1

# Dynamic Port Forwarding with SSH and SOCKS Tunneling

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 10.129.202.64 (ACADEMY-PIVOTING-LINUXPIV)   

Life Left: 167 minute(s)  Terminate 

 SSH to 10.129.202.64 (ACADEMY-PIVOTING-LINUXPIV) with user "ubuntu" and password "HTB_@cademy_stdnt!"

+ 0  You have successfully captured credentials to an external facing Web Server. Connect to the target and list the network interfaces. How many network interfaces does the target web server have? (Including the loopback interface)

```zsh
ubuntu@WEB01:~$ ifconfig | grep inet | grep -v 'inet6' | wc -l
3
```

+ 0  Apply the concepts taught in this section to pivot to the internal network and use RDP (credentials: victor:pass@123) to take control of the Windows target on 172.16.5.19. Submit the contents of Flag.txt located on the Desktop.

```zsh
❯ tail -n 4 /etc/proxychains4.conf
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 9050
socks5  127.0.0.1 1080
```

```zsh
ssh -D 1080 ubuntu@$ip
```

```zsh
proxychains4 xfreerdp3 /v:172.16.5.19 /u:victor /p:pass@123 /dynamic-resolution
```

![](images/1.png)

![](images/2.png)

