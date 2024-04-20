import os
from twilio.rest import Client
from flask import session

# Set environment variables for your credentials
# Read more at http://twil.io/secure
account_sid = os.environ['account_sid']
auth_token = os.environ['auth_token']
verify_sid = os.environ['verify_sid']
client = Client(account_sid, auth_token)
verified_number = None

def send_otp():
    global verified_number
    verified_number = session['phoneno']
    verification = client.verify.v2.services(verify_sid) \
  .verifications \
  .create(to=verified_number, channel="sms")
    print(verification.status)

def verify_otp():
    verified_number = session['phoneno']
    otp_code = session['otp']
    verification_check = client.verify.v2.services(verify_sid) \
  .verification_checks \
  .create(to=verified_number, code=otp_code)
    print(verification_check.status)
    if verification_check.status == 'approved':
        return True
    else: 
        return False





# otp_verification = OTPVerification()
# otp_verification.send_otp("+917310696555")
# otp_verification.verify_otp(1234)