import rsa

def gen_keys():
    pub, priv = rsa.newkeys(1024)
    return pub.save_pkcs1().decode(), priv.save_pkcs1().decode()
