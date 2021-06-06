from Crypto.Cipher import AES
import random
from binascii import a2b_hex, b2a_hex
import Rsa as rsa

ori_request = "You have succeeded!"
e=65537
class WUP:
    def __init__(self,req="",res="",k=""):
        self.request=req
        self.response=res
        self.key=k

class server:
    def __init__(self):
        self.p=rsa.get_prime(512)
        self.q=rsa.get_prime(512)
        self.n=self.p*self.q
        self.eular=(self.p-1)*(self.q-1)
        x, y = rsa.calculate_equation(e,self.eular)
        self.d=x%self.eular
        self.aes=random.randrange(1<<127,2**128) # 128位的key，就是RSA要加密的对称session密钥，且二进制表示下末位要=1
        # print(self.aes)
        while self.aes%2==0:
            self.aes = random.randrange(1 << 127, 2 ** 128)
    def generate_his(self):
        w=WUP()
        request=ori_request
        length=16
        count=len(request)
        if (count%length!=0):
            add=length-(count%length)
        else:
            add=0
        request=request+('\0'*add)
        cryptor=AES.new(a2b_hex(hex(self.aes)[2:]),AES.MODE_ECB) # a2b_hex目的是将128位的密钥转变成binary数据，然后用该密钥生成一个encrypter
        w.request=b2a_hex(cryptor.encrypt(request.encode('utf-8'))) # https://blog.csdn.net/zhangpeterx/article/details/96351648
        # print("w.request", w.request)
        response="Success"
        count = len(response)
        if (count % length != 0):
            add = length - (count % length)
        else:
            add = 0
        response = response + ('\0' * add)
        w.response=b2a_hex(cryptor.encrypt(response.encode('utf-8')))
        w.key=pow(self.aes,e,self.n)
        return w
    def decypt(self,txt):
        decryptor=AES.new(a2b_hex(hex(self.aes)[2:]),AES.MODE_ECB)
        plain_text=str(decryptor.decrypt(a2b_hex(txt)),'utf-8')
        return plain_text.rstrip('\0')
    def test(self,wup):
        aes=bin(pow(wup.key,self.d,self.n))[-128:]
        aes=int(aes,2)
        string=""
        for i in hex(aes)[2:]:
            string+=i
        add=32-len(string)
        string='0'*add+string
        decryptor=AES.new(a2b_hex(string),AES.MODE_ECB)
        plain_text=decryptor.decrypt(a2b_hex(wup.request))
        # print("here!:", plain_text)
        plain_text = b2a_hex(plain_text)
        return plain_text


s=server()
his=s.generate_his()
print("req: ",str(his.request,encoding='utf-8'))
print("res: ",str(his.response,encoding='utf-8'))
print("key: ",his.key)
current_key=0
for i in range(128,0,-1):
    k_i=int(current_key>>1)+(1<<127)
    print("k"+str(i-1),": ",bin(k_i)[2:])
    request="test each bits"
    length = 16
    count = len(request)
    if (count % length != 0):
        add = length - (count % length)
    else:
        add = 0
    request = request + ('\0' * add)
    encryptor=AES.new(a2b_hex(hex(k_i)[2:]),AES.MODE_ECB)
    encrypted=str(b2a_hex(encryptor.encrypt(request.encode('utf-8'))),'utf-8')
    print("encrypted msg: ",encrypted)
    factor=pow(2,(i-1)*e,s.n)
    encrypted_key=pow(his.key*factor,1,s.n)
    re=s.test(WUP(encrypted,"",encrypted_key))
    print("response: ",a2b_hex(re))
    if re== b2a_hex(bytes(request, encoding='utf-8')):
        print("the {0}'th bit from right of session key is {1}".format(129-i, 1))
        current_key=k_i
    else:
        current_key = int(current_key>>1)
        print("the {0}'th bit from right of session key is {1}".format(129-i, 0))
    print("current key: ",current_key)
    print("\n")

decryptor=AES.new(a2b_hex(hex(current_key)[2:]),AES.MODE_ECB)
plain_text=str(decryptor.decrypt(a2b_hex(his.request)),'utf-8') # 这行之所以不能在test函数中使用，是因为str一定要是ASCII码才行，如果test中有x5这样的就不能解释为ASCII码
plain_text=plain_text.rstrip('\0')
print("decrypted request message: ", plain_text)
# print("decrypted request message: ", bytes(plain_text, encoding='utf-8'))
print("original request message:  ", ori_request)
# print("original request message:  ", bytes(ori_request, encoding='utf-8'))
if bytes(plain_text, encoding='utf-8') == bytes(ori_request, encoding='utf-8'):
    print("Correct decryption")
else:
    print("Wrong decryption")
