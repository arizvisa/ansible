assert __import__('os').name == 'nt', 'Module '+__name__+' was accidentally imported on a platform that is not Windows ('+__import__('os').name+').'

import __builtin__
import win32net,win32security,ntsecuritycon
import win32com.client

class Query:
    WmiClient = win32com.client.GetObject('WinMgmts://')

    @staticmethod
    def All(servername=None):
        result,count,resume = win32net.NetGroupEnum(servername, 2)
        assert resume == 0 and len(result) == count, 'Unexpected resume and/or count when calling NetWkstaUserEnum'
        for r in result:
            try:
                res = win32net.NetGroupGetInfo(servername,r['name'],2)
            except:
                res = dict(r)
            res['logon_server'] = servername

            try:
                sid,domain,sidtype = win32security.LookupAccountName(res['logon_server'], res['name'])
            except:
                sid,domain,sidtype = win32security.LookupAccountName(None, res['name'])
            res['user_sid'] = win32security.ConvertSidToStringSid(sid)
            res['logon_domain'] = domain
            res['type'] = sidtype
            yield res

        result,count,resume = win32net.NetLocalGroupEnum(servername, 1)
        assert resume == 0 and len(result) == count, 'Unexpected resume and/or count when calling NetUserEnum'
        for r in result:
            try:
                res = win32net.NetLocalGroupGetInfo(servername,r['name'],1)
            except:
                res = dict(r)
            res['logon_server'] = servername

            sid,domain,sidtype = win32security.LookupAccountName(res['logon_server'], res['name'])
            assert sid == res.setdefault('user_sid',sid)

            if sidtype == win32security.SidTypeAlias:
                res['logon_domain'] = None if domain == 'BUILTIN' else domain
            else:
                res['logon_domain'] = domain
            res['user_sid'] = win32security.ConvertSidToStringSid(res['user_sid'])
            res['group_id'] = int(res['user_sid'].rsplit('-',1)[-1])
            res['type'] = sidtype
            yield res
        return

    @staticmethod
    def ByName(name, servername=None):
        try:
            res = win32net.NetGroupGetInfo(servername,name,2)
        except:
            res = win32net.NetLocalGroupGetInfo(servername,name,1)
        res['logon_server'] = servername

        sid,domain,sidtype = win32security.LookupAccountName(res['logon_server'], name)
        assert sid == res.setdefault('user_sid',sid)

        if sidtype == win32security.SidTypeAlias:
            res['logon_domain'] = None if domain == 'BUILTIN' else domain
        else:
            res['logon_domain'] = domain
        res['user_sid'] = win32security.ConvertSidToStringSid(res['user_sid'])
        res['group_id'] = int(res['user_sid'].rsplit('-',1)[-1])
        res['type'] = sidtype
        return res

    @staticmethod
    def Members(group):
        try:
            result,count,resume = win32net.NetGroupGetUsers(group['logon_server'],group['name'],1)
            assert resume == 0 and len(result) == count, 'Unexpected resume and/or count when calling NetGroupGetUsers'
        except:
            pass
        else:
            for r in result:
                yield r

        try:
            try:
                result,count,resume = win32net.NetLocalGroupGetMembers(group['logon_server'],group['name'],2)
                assert resume == 0 and len(result) == count, 'Unexpected resume and/or count when calling NetGroupGetUsers'
            except:
                result,count,resume =  win32net.NetLocalGroupGetMembers(group['logon_server'],group['name'],1)
                for res in result:
                    res['logon_server'] = group['logon_server']
                    res['logon_domain'] = group['logon_domain']
            else:
                for res in result:
                    res['login_server'] = group['logon_server']
                    if res['domainandname'].startswith(group['logon_domain'] + '\\'):
                        domain,name = res.pop('domainandname').split('\\',1)
                        res['login_domain'] = domain
                        res['name'] = name
                    else:
                        res['name'] = res.pop('domainandname')
                        res['login_domain'] = group['logon_domain']
                    yield res
        except: pass
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
        if gid != int(group.SID.rsplit('-',1)[-1]):
            continue
        members = (r['name'] for r in Query.Members(group))
        return struct_group((group['name'], group.get('password','x'), int(group['user_sid'].rsplit('-',1)[-1]), ','.join(members)))
    raise KeyError, gid

def getgrnam(name):
    try:
        group = Query.ByName(name)
    except:
        raise KeyError, name
    members = (r['name'] for r in Query.Members(group))
    return struct_group((group['name'], group.get('password','x'), int(group['user_sid'].rsplit('-',1)[-1]), ','.join(members)))
def getgrall():
    result = []
    for group in Query.All():
        members = (r['name'] for r in Query.Members(group))
        result.append( struct_group((group['name'], group.get('password','x'), int(group['user_sid'].rsplit('-',1)[-1]), ','.join(members))) )
    return result
