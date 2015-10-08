import __builtin__,os,misc
import win32net,win32com.client,ntsecuritycon

class Query:
    WmiClient = win32com.client.GetObject('WinMgmts://')

    @staticmethod
    def All():
        for account in Query.WmiClient.InstancesOf('Win32_Account'):
            if account.SIDType == ntsecuritycon.SidTypeUser:
                yield account
            continue
        return
    @staticmethod
    def Groups(account):
        groups = Query.WmiClient.ExecQuery('Select GroupComponent From Win32_GroupUser Where PartComponent = "Win32_UserAccount.Domain=\'%s\',Name=\'%s\'"'% (account.Domain,account.Name))
        for idx in xrange(groups.Count):
            yield win32com.client.GetObject(r'WinMgmts:%s'% groups[idx].GroupComponent)
        return
    @staticmethod
    def Group(account):
        return Query.Groups(account).next()
    @staticmethod
    def Gid(account):
        group = Query.Group(account)
        return misc.SID.Identifier(group.SID)
    @staticmethod
    def ByName(domain,name):
        return win32com.client.GetObject(r'WinMgmts:\\.\root\cimv2:Win32_UserAccount.Domain="%s",Name="%s"'%(domain,name))
    @staticmethod
    def Profile(account):
        try:
            profile = win32com.client.GetObject(r'WinMgmts:\\.\root\cimv2:Win32_UserProfile.SID="%s"'%account.SID)
        except:
            # FIXME: no home directory for this account
            return ''
        return profile.LocalPath

class struct_passwd(__builtin__.tuple):
    @property
    def pw_name(self): return self[0]
    @property
    def pw_passwd(self): return self[1]
    @property
    def pw_uid(self): return self[2]
    @property
    def pw_gid(self): return self[3]
    @property
    def pw_gecos(self): return self[4]
    @property
    def pw_dir(self): return self[5]
    @property
    def pw_shell(self): return self[6]
    def __repr__(self): return '{:s}{!r}'.format(self.__class__.__name__, tuple(self))

def getpwnam(name):
    domain = win32net.NetServerGetInfo(None, 100)['name']
    try:
        account = Query.ByName(domain,name)
    except:
        raise KeyError, name
    password = win32net.NetUserGetInfo(None, name, 2)['password']
    gid,profile = Query.Gid(account),Query.Profile(account)
    return struct_passwd((account.Name, password or '*', misc.SID.Identifier(account.SID), gid, account.Description, profile, os.environ['COMSPEC'].replace('\\', '/')))

def getpwuid(uid):
    for account in Query.All():
        if uid != misc.SID.Identifier(account.SID):
            continue
        password = win32net.NetUserGetInfo(None, account.Name, 2)['password']
        gid,profile = Query.Gid(account),Query.Profile(account)
        return struct_passwd((account.Name, password or '*', misc.SID.Identifier(account.SID), gid, account.Description, profile, os.environ['COMSPEC'].replace('\\', '/')))
    raise KeyError, uid

def getpwall():
    result = []
    for account in Query.All():
        password = win32net.NetUserGetInfo(None, account.Name, 2)['password']
        gid,profile = Query.Gid(account),Query.Profile(account)
        result.append( struct_passwd((account.Name, password or '*', misc.SID.Identifier(account.SID), gid, account.Description, profile, os.environ['COMSPEC'].replace('\\', '/'))) )
    return result

