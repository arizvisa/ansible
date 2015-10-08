import __builtin__,os,misc
import win32net,win32com.client,ntsecuritycon

class Query:
    WmiClient = win32com.client.GetObject('WinMgmts://')

    @staticmethod
    def All():
        for account in Query.WmiClient.InstancesOf('Win32_Account'):
            if account.SIDType == ntsecuritycon.SidTypeGroup:
                yield account
            continue
        return
    @staticmethod
    def ByName(domain,name):
        return win32com.client.GetObject(r'WinMgmts:\\.\root\cimv2:Win32_Group.Domain="%s",Name="%s"'%(domain,name))
    @staticmethod
    def Members(group):
        result = Query.WmiClient.ExecQuery('Select PartComponent From Win32_GroupUser Where GroupComponent = "Win32_Group.Domain=\'%s\',Name=\'%s\'"'% (group.Domain,group.Name))
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

class struct_group(__builtin__.tuple):
    @property
    def gr_name(self): return self[0]
    @property
    def gr_passwd(self): return self[1]
    @property
    def gr_gid(self): return self[2]
    @property
    def gr_mem(self): return self[3]
    def __repr__(self): return '{:s}{!r}'.format(self.__class__.__name__, tuple(self))

def getgrgid(gid):
    for group in Query.All():
        if gid != misc.SID.Identifier(group.SID):
            continue
        members = Query.Members(group)
        return struct_group((group.Name, 'x', misc.SID.Identifier(group.SID), ','.join(members)))
    raise KeyError, gid

def getgrnam(name):
    domain = win32net.NetServerGetInfo(None, 100)['name']
    try:
        group = Query.ByName(domain,name)
    except:
        raise KeyError, name
    members = Query.Members(group)
    return struct_group((group.Name, 'x', misc.SID.Identifier(group.SID), ','.join(members)))
def getgrall():
    result = []
    for group in Query.All():
        members = Query.Members(group)
        result.append( struct_group((group.Name, 'x', misc.SID.Identifier(group.SID), ','.join(members))) )
    return result
