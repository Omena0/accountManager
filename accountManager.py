import os
import rsa
import pathlib
import requests

keysdir:str = 'apps'
api_url:str = 'https://Omena0.github.io/api'

os.makedirs(keysdir,exist_ok=True)
apps = os.listdir(keysdir)
licences:dict[dict[str,bytes]] = {}
keys:dict[str,rsa.PublicKey|rsa.PrivateKey] = {}
users:dict[list] = {}

defaultUser = None

def _load_licence(app:str,user:str=None):
    if user is None: user = defaultUser
    if user is None: raise ValueError('No user specified nor default user set.')
    if app not in licences.keys(): licences[app] = {}
    with open(os.path.join(keysdir,app,'users',user), 'rb') as f:
        licences[app][user] = f.read() 

def _load(app:str):
    global users
    # Initialize some paths
    dir = os.path.join(keysdir,app)
    pub_path = os.path.join(dir,'public.key')
    priv_path = os.path.join(dir,'private.key')
    users_path = os.path.join(dir,'users')
    
    os.makedirs(users_path,exist_ok=True)
    
    # Download public key if it doesent exist
    if not os.path.exists(pub_path):
        with open(pub_path,'w') as f: f.write(get_pubkey(app))
    
    # Load users
    if os.path.exists(users_path):
        users[app] = os.listdir(users_path)

    # Load keys
    pub  = pathlib.Path(pub_path).read_text()
    pub = rsa.PublicKey.load_pkcs1(pub)
    
    priv = None
    if os.path.exists(priv_path):
        priv = pathlib.Path(priv_path).read_text()
        priv = rsa.PrivateKey.load_pkcs1(priv)
    return pub, priv

def get_pubkey(app:str,api_url:str=api_url):
    resp = requests.get(f'{api_url}/{app}/keys/public.key')
    resp.raise_for_status()
    return resp.text

def load(app:str='all') -> None:
    global keys, apps
    os.makedirs(keysdir,exist_ok=True)
    apps = os.listdir(keysdir)
    
    if app == 'all':
        for app in apps:
            try:
                keys[app] = _load(app)
                for user in users[app]:
                    _load_licence(app,user)
                    if not check(app,user):
                        licences[app].pop(user)
            except: continue
        return keys
    
    try:
        keys[app] = _load(app)
    
        for user in users[app]:
            _load_licence(app,user)
    except: return None
    
    return keys[app]

def make_keys(app:str):
    pub, priv = rsa.newkeys(2048)

    pub:rsa.PublicKey = pub.save_pkcs1('PEM')
    priv:rsa.PrivateKey = priv.save_pkcs1('PEM')

    with open(os.path.join(keysdir, app, 'public.key'),'wb') as file: file.write(pub)
    
    with open(os.path.join(keysdir, app, 'private.key'),'wb') as file: file.write(priv)

def create_user(app:str,user:str=None):
    if user is None: user = defaultUser
    if user is None: raise ValueError('No user specified nor default user set.')
    
    # If app isint defined already maybe it hasent been loaded?
    if app not in apps: load(app)
    if app not in apps: raise ValueError('App doesent exist.')
    
    dir = os.path.join(keysdir,app,'users',user)
    with open(dir,'wb') as f:
        f.write(b'None')

def create_app(app:str):
    os.makedirs(os.path.join(keysdir,app,'users'),exist_ok=True)
    make_keys(app)
    load(app)

def create_licence(app:str,user:str=None,makeApp=False):
    if user is None: user = defaultUser
    if user is None: raise ValueError('No user specified nor default user set.')
    
    # Create & load app if not already defined
    if app not in apps:
        if not makeApp: raise ValueError('App does not exist. Set makeApp to True to create a new app.')
        create_app(app)
        with open(os.path.join(keysdir,app,'users',user),'wb') as f: f.write(b'None')
        load(app)
        
    # Load app if not loaded
    if app not in keys.items() or app not in licences.items():
        load(app)
    
    if not keys[app][1]: raise ValueError('Private key is either not set or not initialized.')
    key = rsa.sign(user.encode(),keys[app][1],"MD5")
    with open(os.path.join(keysdir,app,'users',user),'wb') as f: f.write(key)
    load(app)
    return key

def setDefault(user:str):
    """Set the default user

    Args:
        user (str): _description_
    """
    global defaultUser
    defaultUser = user

def check(app:str,user:str=None) -> int:
    """Check if a specified user has a licece to an application.

    Args:
        app (str): Application to check for.
        user (str, optional): User to check. Defaults to None.

    Returns:
        int: Status code.
             1: Valid
             0: User doesent have licence
            -1: User doesent exist
            -2: Licence doesent exist
            -3: App doesent exist
            -4 Licence is invalid.
    """
    if app not in apps: return -3
    if user is None: user = defaultUser
    if user is None: raise ValueError('No user specified nor default user set.')

    if not os.path.exists(os.path.join(keysdir,app,'users',user)): return 0
    if app not in licences.keys(): load(app)
    if licences[app][user] == b'None':
        return 0
    
    try: rsa.verify(user.encode(), licences[app][user], keys[app][0])
    except rsa.VerificationError: return -4
    except KeyError: return -2
    else: return 1

def create(app:str,user:str,createLicence:bool=False,createApp:bool=False):
    if user is None: user = defaultUser
    if user is None: raise ValueError('No user specified nor default user set.')
    if app not in apps: load(app)
    if app not in apps: 
        if not createApp: raise ValueError('App dosesent exist.')
        create_app(app)

    if app not in keys.keys(): load(app)
    if app not in keys.keys() and createApp: create_app(app)
    if keys[app][1] and createLicence:
        return create_licence(app,user,createApp)
    return create_user(app,user)
    

__all__ = [keysdir,apps,keys,load,get_pubkey,create_licence,create_user,check,setDefault,make_keys]