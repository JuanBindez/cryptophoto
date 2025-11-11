from cryptophoto import AES256

PASS_WORD = "12345678"
crypt = AES256(password=PASS_WORD)
print(crypt.__repr__)