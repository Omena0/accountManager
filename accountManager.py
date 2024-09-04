import rsa
import json

def gen_keys():
    pub, priv = rsa.newkeys(1024)
    return pub.save_pkcs1().decode(), priv.save_pkcs1().decode()

def gen_licence(user,data,priv):
    if isinstance(priv,str):
        priv = rsa.PrivateKey.load_pkcs1(priv.encode())
    msg = f'{user}|{json.dumps(data)}'.encode()
    signature = rsa.sign(msg, priv,'MD5')
    msg += b'|' + signature
    return msg

def verify_licence(licence,pub):
    if isinstance(pub,str):
        pub = rsa.PublicKey.load_pkcs1(pub.encode())
    user, data, signature = licence.split(b'|')
    msg = user + b'|' + data
    try:
        rsa.verify(msg,signature,pub)
    except Exception:
        return False
    data = json.loads(data)
    return user, data

