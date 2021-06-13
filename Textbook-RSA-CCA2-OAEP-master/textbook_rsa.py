from Rsa import get_random_n_d
import binascii

# size = 1024 # 1024位2进制数的10进制位数在632以下
size = eval(input("\nkey size: "))
e = 65537
n, d = get_random_n_d(size, e)
print("public key, e:", e, ', n:', n)
print("private key, d:", d, ", n:", n)
while True:
    message = input("\nmessage do not exceed 127 char:")
    # message = 'k'*127
    print("the message you input is", message)
    message = bytes(message, encoding='utf-8') # 将该数据用bytes存储，适合传输
    # print(len(message))
    hexmessage =binascii.b2a_hex(message) # message = "kkk", hexmessage = b'6b6b6b
    # print(hexmessage)
    # print(len(hexmessage))
    plaintxt = int(hexmessage, 16)   # int("6b", 16) 意思是将16进制下的6b转换为10进制整数
    if plaintxt >= n:
        print("\033[31;1mplatintxt>n!\033[0m, please cut the information into smaller part and \033[33;1mretry\033[0m.")
    else:
        break
cipher = pow(plaintxt, e, n)
print("encripted= ", cipher)
decipher = pow(cipher, d, n)
int_string = binascii.a2b_hex(hex(decipher)[2:]) # ascii to binary: 6b6b6b to kkk, 跳过16进制表示下的首两位0x
print("decripted= ",str(int_string,encoding='utf-8'))
