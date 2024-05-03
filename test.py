import accountManager as acc
from threading import Thread

acc.load()

def create(app):
    for user in range(20):
        acc.create(str(app),str(user),createLicence=True,createApp=True)
        print(f'Created user {user} in app {app}')
    acc.load(app)

t = []
for app in range(20):
    _t = Thread(target=create,args=[app])
    t.append(_t)
    _t.start()

for i in t:
    i.join()

for app in range(20):
    for user in range(20):
        print(f'Status for User {user} in app {app}: {acc.check(str(app),str(user))}')
