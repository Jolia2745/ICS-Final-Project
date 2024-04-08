
from json import load
import rsa
import base64  # 一种编码  图片---编码  像素点 -- 数字组合

def generateKeys(id):
    (publicKey, privateKey) = rsa.newkeys(1024)    # generate a new key from rsa
    with open('keys/publicKey%s.pem'%id,'wb') as p:       # then save the key into 
        p.write(publicKey.save_pkcs1('PEM'))
    with open('keys/privateKey%s.pem'%id, 'wb') as p:
        p.write(privateKey.save_pkcs1('PEM'))  # generate 一个public key and broacast a public key  /  存在index里面 / 每一个用户都是index里面的一个attribute

def loadKeys(id):
    with open('keys/publicKey%s.pem'%id, 'rb') as p:
        publicKey = rsa.PublicKey.load_pkcs1(p.read())
    with open('keys/privateKey%s.pem'%id, 'rb') as p:
        privateKey = rsa.PrivateKey.load_pkcs1(p.read())
    return privateKey, publicKey    # connect to each other的时候，后台 server 把public 发出去

def encrypted(message,id):
    pri, pub= loadKeys(id)
    key= pub
    

    return base64.b64encode(rsa.encrypt(message.encode('utf-8'), key)).decode('utf-8') # use y 

def decrypted(ciphertext,other_id):  # use other key to decode
    pri, pub= loadKeys(other_id)
    try:
        return rsa.decrypt(base64.b64decode(ciphertext),pri).decode('utf-8')
    except:
        return False

