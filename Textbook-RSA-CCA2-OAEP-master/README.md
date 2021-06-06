# Textbook-RSA-CCA2-OAEP
Implements Textbook RSA and CCA2 attack on it. To defend this attack, I add OAEP padding on RSA

## 在 textbook_rsa里有这么几种转换格式方法

message = bytes("some string", encoding = 'utf-8')
接着 hexmessage = binascii.b2a_hex(message)将字符全部转换为ASCII码，即一个字符变成两个16进制数。
如果还要将此hexmessage变成整数：plaintxt = int(hexmessage,16）意思是将该hexmessage看成是16进制数转变成10进制数。会变得更大（数位会增加）。这时候就能拿去加密了，
要再解密可以用hexmsg = hex(plaintxt)[2:]先转变成16进制，然后int_string = binascii.a2b_hex(hexmsg) 将2位16进制数解读为一个ASCII码，变成binary数据。
最后str(int_string, encoding = 'utf-8')就是string了。可以print。

## 在CCA2里有这么几种转换格式方法，因为用到了AES，所以用起来比较简单，不用人为转换格式

request = "you have succeed" + '\0'*5 凑齐到16位的倍数，至少要是8的倍数因为a2b_hex需要8位一转换8位一转换

random_number = random.randrange(1<<127, 2**128) 生成一个二进制下128位的随机数作为session key

cryptor = AES.new(a2b_hex(hex(random_number)[2:]), AES.MODE_ECB) 生成一个加解密器cryptor，以后既可以cryptor.encrypt(request.enode('utf-8'))，也可以cryptor.decrypt()。 将随机数转化为16进制然后转变为binary数据，这128位的binary数据就是加解密器的session key。

wup.request = b2a_hex(cryptor.encrypt(request.encode('utf-8'))) 意思是先将request内容用encoding的方法变成Binary数据，然后加密，生成的也是binary数据，接着通过b2a的方法变成16进制数，意思是如果直接print会变成 b'8f09...'这样的16进制数，只不过是binary数据。

一个32位的16进制session key用string存储如 ‘0000 f9d2 ...' 也可以直接用在AES里， AES.new(a2b_hex(string), AES.MODE_ECB)也是可以的。  换言之，**a2b_hex()可以让string内的16进制数转变成binary数据**，然后用该解密器解密原本是16进制数据，现在经a2b_hex转变为binary的wup.request,  这个时候print会得到b'test each bits\x00\x00'。  最后再经过b2a_hex转变为16进制是为了好比较，和original message 也化成16进制数比较（如果化成str可能会有无法将该ascii码理解成字符的错误，**总之，a2b_hex就算不是ascii码也可以print，如果是则会print ascii码对应的字符，如果不是会print\x92类似的，但str()如果不是ascii码会报错！**就像下面b'test each bits\x00\x00'） 

```python
string='0'*add+string
decryptor=AES.new(a2b_hex(string),AES.MODE_ECB)
plain_text=decryptor.decrypt(a2b_hex(wup.request))
#print("here!:", plain_text) # b'test each bits\x00\x00'
plain_text = b2a_hex(plain_text)
```

