Started of the CTF with a traditional nmap scan

nmap -A -p- -T4 10.10.10.3
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-29 06:35 EDT
Nmap scan report for 10.10.10.3
Host is up (0.18s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          vsftpd 2.3.4
22/tcp   open  ssh          OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn?
445/tcp  open  netbios-ssn  Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3632/tcp open  distccd      distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.4.7 (92%), Linksys WRV54G WAP (91%), Linux 2.6.23 (90%), Linux 2.6.8 - 2.6.30 (90%), Arris TG562G/CT cable modem (88%), Dell Integrated Remote Access Controller (iDRAC6) (88%), Linux 2.4.21 - 2.4.31 (likely embedded) (88%), Dell iDRAC 6 remote access controller (Linux 2.6) (88%), OpenWrt 0.9 - 7.09 (Linux 2.4.30 - 2.4.34) (88%), OpenWrt Kamikaze 7.09 (Linux 2.6.22) (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: 27s

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   173.34 ms 10.10.14.1
2   174.42 ms 10.10.10.3

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 576.99 seconds
