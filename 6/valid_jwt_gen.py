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

tok = generate_token()

print(tok)
