# Firewall and IDS/IPS Evasion - Easy Lab
```zsh
❯ sudo nmap -p 22 -sV --script ssh2-enum-algos -Pn -n -T2 -e tun0 10.129.2.80 

Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-23 04:07 EDT Nmap scan report for 10.129.2.80 Host is up (0.28s latency). PORT STATE SERVICE VERSION 22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0) | ssh2-enum-algos: | kex_algorithms: (10) | curve25519-sha256 | curve25519-sha256@libssh.org | ecdh-sha2-nistp256 | ecdh-sha2-nistp384 | ecdh-sha2-nistp521 | diffie-hellman-group-exchange-sha256 | diffie-hellman-group16-sha512 | diffie-hellman-group18-sha512 | diffie-hellman-group14-sha256 | diffie-hellman-group14-sha1 | server_host_key_algorithms: (5) | ssh-rsa | rsa-sha2-512 | rsa-sha2-256 | ecdsa-sha2-nistp256 | ssh-ed25519 | encryption_algorithms: (6) | chacha20-poly1305@openssh.com | aes128-ctr | aes192-ctr | aes256-ctr | aes128-gcm@openssh.com | aes256-gcm@openssh.com | mac_algorithms: (10) | umac-64-etm@openssh.com | umac-128-etm@openssh.com | hmac-sha2-256-etm@openssh.com | hmac-sha2-512-etm@openssh.com | hmac-sha1-etm@openssh.com | umac-64@openssh.com | umac-128@openssh.com | hmac-sha2-256 | hmac-sha2-512 | hmac-sha1 | compression_algorithms: (2) | none |_ zlib@openssh.com Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . Nmap done: 1 IP address (1 host up) scanned in 4.60 seconds
```

Our client wants to know if we can identify which operating system their provided machine is running on. Submit the OS name as the answer:
# `Ubuntu`

### **1. Hiểu Logic Của Hệ Thống**

- **Mục tiêu**:
    
    - Xác định OS của máy `http://<target>/status.php` mà không bị phát hiện.
        
    - Host trong cùng subnet `/24` bị chặn giao tiếp → Tránh dùng ARP, gói tin local.
        
- **Gợi ý**: Dịch vụ mạng (HTTP, SSH, SMB) có thể tiết lộ OS qua banner hoặc headers.
    

---

### **2. Chiến Lược Tối Ưu**

#### **a. Sử dụng HTTP/HTTPS để Thu Thập Thông Tin**

- **Bước 1**: Kiểm tra header HTTP/HTTPS để lấy thông tin server (thường chứa OS):
    ```bash
curl -I http://<target>/status.php
    ```

    → Tìm trường `Server` hoặc `X-Powered-By` (VD: `Apache/2.4.29 (Ubuntu)`).
    
- **Bước 2**: Nếu không thành công, dùng Nmap script `http-title`:
    
    ```zsh
sudo nmap -p 80,443 --script http-title --script-args http.useragent="Mozilla/5.0" -Pn -n -T2 <target>
    ```
    → Tránh detection bằng cách giả mạo User-Agent và tắt DNS resolution.
    

#### **b. Quét Cổng SSH (Port 22)**

- SSH thường tiết lộ OS qua banner:
    ```zsh
sudo nmap -p 22 -sV --script ssh2-enum-algos -Pn -n -T2 <target>
    ```

    → Kiểm tra kết quả `Service Info: OS: Linux` hoặc `Windows`.
    

#### **c. OS Detection Tối Ưu với Nmap**

- **Câu lệnh**:
    ```zsh
sudo nmap -O -Pn -n -f --scan-delay 3s --max-retries 1 -T2 -e <interface> --disable-arp-ping <target>
    ```
    **Giải thích**:
    
    - **`-O`**: OS detection.
        
    - **`-Pn`**: Bỏ qua host discovery (tránh gửi ICMP/ARP).
        
    - **`-n`**: Tắt DNS resolution.
        
    - **`-f`**: Fragment gói tin để qua mặt IDS.
        
    - **`--scan-delay 3s`**: Giảm tốc độ scan.
        
    - **`-T2`**: Chế độ "Sneaky" để tránh detection.
        
    - **`-e <interface>`**: Chỉ định interface (VD: `tun0` cho VPN).
        

#### **d. Sử dụng Decoy IP Khác Subnet**

- Thêm IP mồi từ subnet khác để đánh lạc hướng:
    ```zsh
sudo nmap -O -Pn -n -D 192.168.100.1,192.168.200.1,ME -f --scan-delay 3s -T2 -e <interface> <target>
    ```
    → Chọn IP mồi không thuộc `/24` của target.
    

---

### **3. Kiểm Tra Kết Quả Trên `status.php`**

Sau mỗi lần quét, truy cập `http://<target>/status.php` để xem IDS/IPS có phát hiện hay không:

- Nếu trang hiển thị **"No alerts triggered"** → Thành công.
    
- Nếu bị phát hiện → Điều chỉnh tham số (tăng `--scan-delay`, thêm decoy, v.v.).
    

---

### **4. Ví Dụ Thực Tế**

Giả sử target là `10.129.2.80` và interface VPN là `tun0`:
# Bước 1: Thu thập HTTP header
```zsh
curl -I http://10.129.2.80/status.php
```
# Bước 2: Quét SSH
```zsh
sudo nmap -p 22 -sV --script ssh2-enum-algos -Pn -n -T2 -e tun0 10.129.2.80
```
# Bước 3: OS Detection tối ưu
```zsh
sudo nmap -O -Pn -n -f --scan-delay 3s --max-retries 1 -T2 -e tun0 --disable-arp-ping 10.129.2.80
```
# Bước 4: Kiểm tra status.php
```zsh
curl http://10.129.2.80/status.php
```
---

### **5. Lưu Ý Quan Trọng**

- **Tránh subnet `/24`**: Đảm bảo IP nguồn không thuộc cùng subnet với target (dùng VPN hoặc proxy).
    
- **Giảm tối đa traffic**: Chỉ quét cổng cần thiết (80, 443, 22) thay vì toàn bộ.
    
- **Thử nghiệm từng bước**: Thay đổi từng tham số để xác định nguyên nhân bị phát hiện.

### **1. Câu Lệnh Được Sử Dụng**
#### **Giải thích tùy chọn**:

```zsh
sudo nmap -p 22 -sV --script ssh2-enum-algos -Pn -n -T2 -e tun0 10.129.2.80
```

- **`-p 22`**: Chỉ quét cổng SSH (22) → Giảm traffic, tập trung vào dịch vụ có thể tiết lộ OS.
    
- **`-sV`**: Phát hiện phiên bản dịch vụ → Xác định OpenSSH version.
    
- **`--script ssh2-enum-algos`**: Liệt kê các thuật toán mã hóa mà SSH server hỗ trợ → Dấu hiệu nhận biết OS.
    
- **`-Pn`**: Bỏ qua host discovery → Tránh gửi ICMP/ARP.
    
- **`-n`**: Không resolve DNS → Giảm "noise".
    
- **`-T2`**: Chế độ "Sneaky" → Tốc độ chậm để tránh detection.
    
- **`-e tun0`**: Chỉ định interface VPN → Đảm bảo gói tin đi đúng hướng.
### **2. Kết Quả Chi Tiết**

#### **a. Thông tin dịch vụ SSH**:
```zsh
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
```
- **OpenSSH 7.6p1**: Phiên bản OpenSSH này thường đi kèm với **Ubuntu 18.04 LTS (Bionic Beaver)**.
    
- **Ubuntu 4ubuntu0.7**: Đây là phần mở rộng của Ubuntu, cho biết hệ thống đang chạy **Ubuntu Linux**.
    

#### **b. Kết quả script `ssh2-enum-algos`**:

Liệt kê các thuật toán được hỗ trợ:

- **`kex_algorithms`**: Thuật toán trao đổi khóa (ví dụ: `curve25519-sha256`, `diffie-hellman-group14-sha256`).
    
- **`server_host_key_algorithms`**: Thuật toán khóa máy chủ (ví dụ: `ssh-rsa`, `ecdsa-sha2-nistp256`).
    
- **`encryption_algorithms`**: Thuật toán mã hóa (ví dụ: `aes256-ctr`, `chacha20-poly1305@openssh.com`).
    
- **`mac_algorithms`**: Thuật toán MAC (ví dụ: `hmac-sha2-256`, `umac-64-etm@openssh.com`).
    
- **`compression_algorithms`**: Thuật toán nén (ví dụ: `none`, `zlib@openssh.com`).
    

→ **Tại sao quan trọng?**  
Các thuật toán mặc định và phiên bản OpenSSH thường **gắn liền với OS cụ thể**. Ví dụ:

- **Ubuntu/Debian**: Thường hỗ trợ `curve25519-sha256` và `aes256-gcm@openssh.com`.
    
- **Red Hat/CentOS**: Có xu hướng sử dụng các thuật toán cũ hơn như `diffie-hellman-group14-sha1`.
    

#### **c. Thông tin OS từ dịch vụ**:
```zsh
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- **`OS: Linux`**: Xác nhận hệ điều hành là Linux.
    
- **`CPE: cpe:/o:linux:linux_kernel`**: Chuẩn CPE cho biết kernel Linux → Không xác định chính xác distro, nhưng kết hợp với phiên bản OpenSSH, ta suy ra **Ubuntu**.
    

---

### **3. Tại Sao Điều Này Giúp Xác Định OS?**

- **Phiên bản OpenSSH**: Mỗi distro Linux có phiên bản OpenSSH riêng. Ví dụ:
    
    - **Ubuntu 18.04**: OpenSSH 7.6p1.
        
    - **Ubuntu 20.04**: OpenSSH 8.2p1.
        
- **Cấu hình mặc định**: Các thuật toán và tùy chọn được kích hoạt mặc định thay đổi theo distro. Ví dụ:
    
    - **Ubuntu**: Kích hoạt `chacha20-poly1305@openssh.com` từ sớm.
        
    - **CentOS**: Thường chậm hơn trong việc hỗ trợ các thuật toán mới.
        

---

### **4. Tại Sao Lệnh Này Tránh Được IDS/IPS?**

- **Tập trung vào một cổng**: Chỉ quét cổng 22 → Giảm số gói tin gửi đi.
    
- **Không gửi gói thừa**:
    
    - `-Pn`: Không gửi ICMP/ARP.
        
    - `-n`: Không truy vấn DNS.
        
- **Tốc độ chậm**: `-T2` tránh flood gói tin.
    
- **Script tinh tế**: `ssh2-enum-algos` không thực hiện các thao tác xâm nhập (như brute force) → Ít gây nghi ngờ.
    

---

### **5. Kết Luận**

- **OS chính xác**: Ubuntu 18.04 LTS (dựa trên OpenSSH 7.6p1 và chuỗi phiên bản `Ubuntu 4ubuntu0.7`).
    
- **Cơ sở dữ liệu tham khảo**:
    
    - [OpenSSH Version ↔ OS Mapping](https://launchpad.net/ubuntu/+source/openssh)
        
    - [CPE Database](https://nvd.nist.gov/products/cpe).
# Firewall and IDS/IPS Evasion - Medium Lab

```zsh
sudo nmap -sU -p 53 --script dns-nsid -Pn -n -T2 --scan-delay 3s -e tun0 10.129.149.155
```

```zsh
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-23 04:35 EDT
Nmap scan report for 10.129.149.155
Host is up (0.28s latency).

PORT   STATE SERVICE
53/udp open  domain
| dns-nsid: 
|_  bind.version: HTB{GoTtgUnyze9Psw4vGjcuMpHRp}

Nmap done: 1 IP address (1 host up) scanned in 3.94 seconds

```
### **1. Sử dụng Nmap với Script `dns-nsid`**

**Câu lệnh**:

```zsh
sudo nmap -sU -p 53 --script dns-nsid -Pn -n -T2 --scan-delay 3s -f -e tun0 <target>
```
**Giải thích**:

- **`-sU`**: Quét UDP (DNS chạy trên UDP port 53).
    
- **`-p 53`**: Tập trung vào cổng DNS.
    
- **`--script dns-nsid`**: Lấy thông tin Nameserver ID (thường chứa phiên bản DNS server).
    
- **`-Pn`**: Bỏ qua host discovery.
    
- **`-n`**: Không resolve DNS.
    
- **`-T2`**: Chế độ "Sneaky" để tránh detection.
    
- **`--scan-delay 3s`**: Thêm độ trễ giữa các gói tin.
    
- **`-f`**: Fragment gói tin để qua mặt IDS.
    
- **`-e tun0`**: Chỉ định interface VPN (thay `tun0` bằng interface của bạn).
    

**Kết quả mẫu**:
```zsh
PORT   STATE SERVICE
53/udp open  domain
| dns-nsid: 
|_  bind.version: "9.16.1-Ubuntu"  # Phiên bản DNS server
```
---

### **2. Sử dụng Dig để Truy vấn Trực tiếp**

**Câu lệnh**:
```zsh
dig CHAOS TXT version.bind @<target>
```
**Giải thích**:

- **`CHAOS`**: Loại truy vấn đặc biệt để lấy thông tin server.
    
- **`TXT version.bind`**: Truy vấn bản ghi TXT `version.bind` (nhiều DNS server như BIND trả về phiên bản tại đây).
    

**Kết quả mẫu**:
```zsh
;; ANSWER SECTION:
version.bind.     0    CHAOS    TXT    "9.16.1-Ubuntu"
```
---

### **3. Giải Thích Logic**

- **Tại sao DNS server tiết lộ phiên bản?**  
    Nhiều DNS server (vd: **BIND**) mặc định hiển thị phiên bản trong response để debug, nhưng điều này có thể bị tắt trong cấu hình bảo mật.
    
- **Cách tránh firewall/IDS**:
    
    - **UDP scan** ít bị chú ý hơn TCP.
        
    - **Fragment gói tin** (`-f`) và **độ trễ** (`--scan-delay`) giảm nguy cơ phát hiện.
        
    - Truy vấn `version.bind` là truy vấn DNS hợp lệ, khó phân biệt với traffic thông thường.
        

---

### **4. Lưu Ý Quan Trọng**

- **Firewall có thể chặn UDP/53**: Nếu không nhận phản hồi, thử dùng TCP:
    ```zsh
    sudo nmap -sT -p 53 --script dns-nsid <target>  # Quét TCP port 53
    ```
- **Kiểm tra lại `status.php`**: Đảm bảo IDS/IPS không phát hiện scan.
    

---

### **Kết Quả Mong Đợi**

Phiên bản DNS server thường có dạng:

- **BIND**: `"9.16.1-Ubuntu"`, `"9.18.18"`.
    
- **Microsoft DNS**: Không trả về `version.bind`.

# Firewall and IDS/IPS Evasion - Hard Lab

đầu tiên check xem port 53 của cả UDP và TCP, thì của TCP là filtered => dùng `--source-port 53`
```zsh
sudo nmap --disable-arp-ping -sS -p- -T3 -Pn -n --source-port 53 --max-retries 3 -D RND:5,ME -e tun0 10.129.2.47 -vv
```

thấy cổng 50000 mở

tiếp dùng nc/ncat lấy flag

```zsh
❯ sudo ncat -nv --source-port 53 10.129.2.47 50000
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Connected to 10.129.2.47:50000.
220 HTB{kjnsdf2n982n1827eh76238s98di1w6}
```
hoặc
```zsh
❯ sudo nc -nvp 53 10.129.2.47 50000
(UNKNOWN) [10.129.2.47] 50000 (?) open
220 HTB{kjnsdf2n982n1827eh76238s98di1w6}
```

