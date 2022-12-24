import jwt

uid = 45863
secret = "cZdOWcchwaCxR9UwWq27bALMPIMk6Tsy"

hmac = "7c4x7hYaNgFvBckbwjfHs5h2lbUKInZJ"

header = {
  "typ": "JWT",
  "alg": "HS256"
}

payload = {
  "iat": 1653578127,
  "exp": 2666170127,
  "sec": secret,
  "uid": uid
}

print(jwt.encode(payload, hmac, algorithm='HS256'))#.decode())
