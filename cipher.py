
from json import load
import rsa
import base64 

def generateKeys(id):
    (publicKey, privateKey) = rsa.newkeys(1024)    # generate a new key from rsa
    with open('keys/publicKey%s.pem'%id,'wb') as p:       # then save the key into 
        p.write(publicKey.save_pkcs1('PEM'))
    with open('keys/privateKey%s.pem'%id, 'wb') as p:
        p.write(privateKey.save_pkcs1('PEM'))  # generate 一个public key and broacast a public key which stored in an index. Each user is an attribute of an index.

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

