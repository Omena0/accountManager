import accountManager as acc

pub, priv = acc.gen_keys()

licence = acc.gen_licence('Omena0',{'expirationDate':1000},priv)

print(acc.verify_licence(licence,pub))

