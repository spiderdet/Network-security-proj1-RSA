import Rsa_OAEP
from Rsa import get_random_n_d
from CCA2 import WUP, server

# size = 1024
size = eval(input("\nkey size: "))
e = 65537
n, d = get_random_n_d(size, e)
print("public key, e:", e, ', n:', n)
print("private key, d:", d, ", n:", n)
# instr = "OAEP test message"
instr = input("\nmessage= ")
instr = bytes(instr, encoding='utf-8')
encrypted_msg = Rsa_OAEP.encode(n, e, instr)
print("\nencripted= ", encrypted_msg)
decrypted_msg= Rsa_OAEP.decode([n, d], 0, encrypted_msg)
print("decripted= ", str(decrypted_msg, encoding='utf-8'))

