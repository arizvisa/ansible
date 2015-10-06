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
    def Members(group):
        result = WmiClient.ExecQuery('Select PartComponent From Win32_GroupUser Where GroupComponent = "Win32_Group.Domain=\'%s\',Name=\'%s\'"'% (group.Domain,group.Name))
        for index in range(0,len(result)):
            record = result[index]
            try:
                user = win32com.client.GetObject(r'WinMgmts:%s'% record.PartComponent)
            except:
                # fall-back to generating a member name from the domain and user attributes
                domain,user = record.PartComponent.split(':',1)[1].split('.',1)[1].split(',',1)
                domain,user = (n.split('=',1)[1].replace('"','') for n in (domain,user))
                res = r'\\'.join((domain,user))
            else:
                res = user.Name
            yield res
        return

def getgrgid(gid):
    for group in WmiClient.InstancesOf('Win32_Group'):
        if gid != SID.Identifier(group.SID):
            continue
        members = Query.Members(group)
        return (group.Name, 'x', SID.Identifier(group.SID), ','.join(members))
    raise KeyError, gid

def getgrnam(name):
    domain = win32net.NetServerGetInfo(None, 100)['name']
    try:
        group = win32com.client.GetObject(r'WinMgmts:\\.\root\cimv2:Win32_Group.Domain="%s",Name="%s"'%(domain,name))
    except:
        raise KeyError, name
    members = Query.Members(group)
    return (group.Name, 'x', SID.Identifier(group.SID), ','.join(members))
def getgrall():
    result = []
    for group in WmiClient.InstancesOf('Win32_Group'):
        members = Query.Members(group)
        result.append( (group.Name, 'x', SID.Identifier(group.SID), ','.join(members)) )
    return result
