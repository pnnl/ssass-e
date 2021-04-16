import json
from cryptography.fernet import Fernet

fr = open("credsSafe", "rb")
credsSafe = fr.read()
fr.close()

fr = open("ssasse_platform/InferenceEngine/Scans/creds.json", "r", encoding="utf-8")
credsJson = json.loads(fr.read())
fr.close()

cipher_suite = Fernet(credsSafe)

for ip,credsDict in credsJson.items():
    print(credsDict["DEFAULT_CREDS"][0])
    print(credsDict["DEFAULT_CREDS"][1])
    encrypted_password_str = credsDict["DEFAULT_CREDS"][1]
    encrypted_password_b = encrypted_password_str.encode()
    print(encrypted_password_b)
    decrypted_password_b = cipher_suite.decrypt(encrypted_password_b)
    print(decrypted_password_b)
    decrypted_password_str = decrypted_password_b.decode()
    print(decrypted_password_str)
