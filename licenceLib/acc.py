from licenceLib.keys import gen_keys
import urllib.request
import subprocess
import time as t
import ntplib
import socket
import json
import rsa
import os

def gen_licence(user, priv, data=None):
    if data is None:
        data = {}
    if isinstance(priv,str):
        priv = rsa.PrivateKey.load_pkcs1(priv.encode())
    msg = f'{user}||{json.dumps(data)}'.encode()
    signature = rsa.sign(msg, priv,'MD5')
    msg += b'||' + signature
    return msg

def gen_extras(data,user:str='', expirationDate:str='',hwid:str='', publicIP:str='', localIP:str=''):
    if user:
        data['user'] = user

    if expirationDate:
        online = expirationDate.startswith('O')
        time = float(expirationDate.removeprefix('O'))
        data[f'expirationDate{'Online' if online else ''}'] = int(t.time()+time)
    
    if hwid:
        data['hwid'] = hwid
    
    if publicIP:
        data['publicIP'] = publicIP
    
    if localIP:
        data['localIP'] = localIP


    return data

def get_hwid():
    return subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()

def get_onlinetime():
    return ntplib.NTPClient().request('pool.ntp.org').tx_time

def get_public_ip():
    return urllib.request.urlopen('https://ident.me').read().decode('utf8')

def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

def verify_licence(licence,pub, extras = False):
    if isinstance(pub,str):
        pub = rsa.PublicKey.load_pkcs1(pub.encode())
    user, data, signature = licence.split(b'||',2)
    msg = user + b'||' + data
    try: rsa.verify(msg,signature,pub)
    except Exception:
        return False, 'InvalidSignature'

    if extras:
        extras = verify_extras(licence)
    if extras:
        return False, extras

    data = json.loads(data)
    return True, user, data

def verify_extras(licence):
    user, data, signature = licence.split(b'||',2)
    data = json.loads(data)
    result = []

    if 'user' in data and data['user'] != user:
        result.append('InvalidName')

    if 'expirationDate' in data and int(t.time()) > int(data['expirationDate']):
        result.append('LicenceExpired')

    if 'expirationDateOnline' in data and int(get_onlinetime()) > int(data['expirationDateOnline']):
        result.append('LicenceExpiredOnline')

    if 'hwid' in data and get_hwid() != data['hwid']:
        result.append('InvalidHWID')
    
    if 'localIP' in data and get_local_ip() != data['localIP']:
        result.append('InvalidLocalIP')

    if 'publicIP' in data and get_public_ip() != data['publicIP']:
        result.append('InvalidPublicIP')

    return result

def load_keys(dir='.'):
    pub = None
    priv = None
    if os.path.exists(f'{dir}/public.key'):
        with open(f'{dir}/public.key','rb') as f:
            pub = rsa.PublicKey.load_pkcs1(f.read())
    if os.path.exists(f'{dir}/private.key'):
        with open(f'{dir}/private.key','rb') as f:
            priv = rsa.PrivateKey.load_pkcs1(f.read())
    return pub,priv

def load_licence(dir='.'):
    try:
        with open(f'{dir}/licence', 'rb') as f:
            return f.read()
    except Exception: ...

def save_keys(dir='.',pub=None,priv=None):
    if pub:
        if isinstance(pub,str):
            pub = rsa.PublicKey.load_pkcs1(pub)
        with open(f'{dir}/public.key','wb') as f:
            f.write(pub.save_pkcs1())
    if priv:
        if isinstance(priv,str):
            priv = rsa.PrivateKey.load_pkcs1(priv)
        with open(f'{dir}/private.key','wb') as f:
            f.write(priv.save_pkcs1())

def save_licence(licence,dir='.'):
    with open(f'{dir}/licence','wb') as f:
        f.write(licence)

