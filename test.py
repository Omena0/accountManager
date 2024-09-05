import licenceLib.acc as acc

pub, priv = acc.load_keys()

if not (pub and priv):
    pub, priv = acc.gen_keys()
    acc.save_keys('.',pub,priv)

licence = acc.load_licence()


if not licence:
    data = acc.gen_extras({},user='urmom',expirationDate='1',hwid='bingchilling',publicIP='real',localIP='frf')
    licence = acc.gen_licence('Omena0',priv,data)
    acc.save_licence(licence)

valid, *data = acc.verify_licence(licence, pub, True)

if valid:
    print(f'Licence is valid! {data}')

else:
    print(f'Licence is invalid! {data}')
