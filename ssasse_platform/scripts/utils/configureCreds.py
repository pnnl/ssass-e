import json
from cryptography.fernet import Fernet

credsSafe = ""
try:
    fr = open("credsSafe", "rb")
    credsSafe = fr.read()
    fr.close()
except:
    credsSafe = Fernet.generate_key()
    fw = open("credsSafe", "wb")
    fw.write(credsSafe)
    fw.close()

credsJson = {}

try:
    fr = open("ssasse_platform/InferenceEngine/Scans/creds.json", "r", encoding="utf-8")
    credsJson = json.loads(fr.read())
    fr.close()
except Exception:
    print("Exception loading ssasse_platform/InferenceEngine/Scans/creds.json")

ip = input("Enter ip of device: ")
user = input("Enter username: ")
password = input("Enter password: ").encode()

cipher_suite = Fernet(credsSafe)
encrypted_password_b = cipher_suite.encrypt(password)

if ip not in credsJson:
    credsJson[ip] = {"DEFAULT_CREDS": [user, encrypted_password_b.decode()]}
if "DEFAULT_CREDS" not in credsJson[ip]:
    credsJson[ip]["DEFAULT_CREDS"] = [user, encrypted_password_b.decode()]

fw = open("ssasse_platform/InferenceEngine/Scans/creds.json", "w+", encoding="utf-8")
fw.write(json.dumps(credsJson))
fw.close()
