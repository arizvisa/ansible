import win32net,win32com.client,os

WmiClient = win32com.client.GetObject('WinMgmts://')

class SID:
    @staticmethod
    def unpack(sid):
        SidVersion = '-'.join(sid.split('-',2)[:2])
        SubAuthorityCount = int(sid.split('-')[2])
        assert SubAuthorityCount > 2, 'Invalid SID'
        res = sid.split('-')[3:]
        AuthorityIdentifier = int(res.pop(0))
        #FIXME: is raymond wrong when dealing with group SIDs here?
        #MachineId = map(res.pop, (0,)*(SubAuthorityCount-2))
        MachineId = map(res.pop, (0,)*(len(res)-1))
        UserId = res.pop(0)
        assert len(res) == 0, 'Invalid SID'
        return SidVersion,SubAuthorityCount,AuthorityIdentifier,map(int,MachineId),UserId
    @classmethod
    def SidVersion(cls, sid):
        return int(cls.unpack(sid)[0].split('-',1)[1])
    @classmethod
    def SubAuthority(cls, sid):
        return cls.unpack(sid)[1]
    @classmethod
    def AuthorityIdentifier(cls, sid):
        return cls.unpack(sid)[2]
    @classmethod
    def MachineIdentifier(cls, sid):
        # FIXME: raymond chen says that these should be endian-flipped.
        #        It's a unique id for machines, so it only matters if we actually
        #        compare them to another one
        return reduce(lambda t,v: t*0x100000000+v, cls.unpack(sid)[3], long(0))
    @classmethod
    def Identifier(cls, sid):
        return int(cls.unpack(sid)[4])

class Query:
    @staticmethod
    def Gid(account):
        res, = WmiClient.ExecQuery('Select GroupComponent From Win32_GroupUser Where PartComponent = "Win32_UserAccount.Domain=\'%s\',Name=\'%s\'"'% (account.Domain,account.Name))
        group = win32com.client.GetObject(r'WinMgmts:%s'% res.GroupComponent)
        return SID.Identifier(group.SID)

    @staticmethod
    def Profile(account):
        try:
            profile = win32com.client.GetObject(r'WinMgmts:\\.\root\cimv2:Win32_UserProfile.SID="%s"'%account.SID)
        except:
            # FIXME: no home directory for this account
            return ''
        return profile.LocalPath

def getpwnam(name):
    domain = win32net.NetServerGetInfo(None, 100)['name']
    try:
        account = win32com.client.GetObject(r'WinMgmts:\\.\root\cimv2:Win32_UserAccount.Domain="%s",Name="%s"'%(domain,name))
    except:
        raise KeyError, name
    password = win32net.NetUserGetInfo(None, name, 2)['password']
    gid,profile = Query.Gid(account),Query.Profile(account)
    return (account.Name, password or '*', SID.Identifier(account.SID), gid, account.Description, profile, os.environ['COMSPEC'].replace('\\', '/'))

def getpwuid(uid):
    for account in WmiClient.InstancesOf('Win32_UserAccount'):
        if uid != SID.Identifier(account.SID):
            continue
        password = win32net.NetUserGetInfo(None, account.Name, 2)['password']
        gid,profile = Query.Gid(account),Query.Profile(account)
        return (account.Name, password or '*', SID.Identifier(account.SID), gid, account.Description, profile, os.environ['COMSPEC'].replace('\\', '/'))
    raise KeyError, uid

def getpwall():
    result = []
    for account in WmiClient.InstancesOf('Win32_UserAccount'):
        password = win32net.NetUserGetInfo(None, account.Name, 2)['password']
        gid,profile = Query.Gid(account),Query.Profile(account)
        result.append( (account.Name, password or '*', SID.Identifier(account.SID), gid, account.Description, profile, os.environ['COMSPEC'].replace('\\', '/')) )
    return result

