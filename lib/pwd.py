assert __import__('os').name == 'nt', 'Module '+__name__+' was accidentally imported on a platform that is not Windows ('+__import__('os').name+').'

import __builtin__,os
import win32net,win32security,ntsecuritycon
import win32com.client

class Query:
    WmiClient = win32com.client.GetObject('WinMgmts://')

    @staticmethod
    def All(servername=None):
        lastserver = servername
        result,count,resume = win32net.NetWkstaUserEnum(servername, 1)
        assert resume == 0 and len(result) == count, 'Unexpected resume and/or count when calling NetWkstaUserEnum'
        for r in result:
            try:
                res = win32net.NetUserGetInfo(r['logon_server'] or lastserver,r['username'],4)
                res.setdefault('logon_domain', r['logon_domain'])
                if res['logon_server'] == '\\\\*':
                    res['logon_server'] = r['logon_server'] or lastserver
            except:
                res = dict(r)
                res['name'] = res.pop('username')

            try:
                sid,domain,sidtype = win32security.LookupAccountName(r['logon_server'], r['username'])
            except:
                sid,domain,sidtype = win32security.LookupAccountName(lastserver, r['username'])
            assert sid == res.setdefault('user_sid',sid) and domain == res.setdefault('logon_domain', domain)
            res['user_sid'] = win32security.ConvertSidToStringSid(res['user_sid'])
            res['type'] = sidtype
            yield res
            lastserver = res['logon_server'] or lastserver

        result,count,resume = win32net.NetUserEnum(servername, 1)
        assert resume == 0 and len(result) == count, 'Unexpected resume and/or count when calling NetUserEnum'
        for r in result:
            try:
                res = win32net.NetUserGetInfo(servername, r['name'], 4)
                if res['logon_server'] == '\\\\*':
                    res['logon_server'] = None
            except:
                res = dict(r)
                res['logon_server'] = None

            sid,domain,sidtype = win32security.LookupAccountName(None, r['name'])
            assert sid == res.setdefault('user_sid',sid) and domain == res.setdefault('logon_domain',domain)
            res['user_sid'] = win32security.ConvertSidToStringSid(res['user_sid'])
            res['type'] = sidtype
            yield res
        return

    @staticmethod
    def NetGroups(user):
        for name,attrs in win32net.NetUserGetGroups(user['logon_server'], user['name']):
            try:
                res = win32net.NetGroupGetInfo(user['logon_server'], name, 2)
            except:
                res = {'name':name,'attributes':attrs}

            sid,domain,sidtype = win32security.LookupAccountName(user['logon_server'], name)
            assert domain == user['logon_domain']
            res.setdefault('logon_domain', domain)
            res.setdefault('user_sid', sid)
            res['user_sid'] = win32security.ConvertSidToStringSid(res['user_sid'])
            res.update({'logon_server':user['logon_server'], 'sidtype':sidtype})
            yield res
        return

    @staticmethod
    def LocalGroups(user):
        for name in win32net.NetUserGetLocalGroups(user['logon_server'], user['name']):
            try:
                res = win32net.NetLocalGroupGetInfo(user['logon_server'], name, 1)
            except:
                res = {'name':name}
            try:
                sid,domain,sidtype = win32security.LookupAccountName(user['logon_server'], name)
            except:
                sid,domain,sidtype = win32security.LookupAccountName(None, name)
            if sidtype == win32security.SidTypeAlias:
                res.update({'user_sid':sid,'logon_domain':None if domain == 'BUILTIN' else domain,'type':sidtype})
            else:
                assert domain == user['logon_domain']
                res.update({'user_sid':sid,'logon_domain':domain,'type':sidtype})
            res['user_sid'] = win32security.ConvertSidToStringSid(res['user_sid'])
            yield res
        return

    @staticmethod
    def Group(user):
        local = Query.LocalGroups(user)
        network = Query.NetGroups(user)
        try:
            return local.next()
        except: pass
        try:
            return network.next()
        except: pass
        # default to the Guest's Groups
        user = Query.ByName('Guest', None)
        return Query.LocalGroups(user).next()

    @staticmethod
    def Gid(user):
        group = Query.Group(user)
        return int(group['user_sid'].rsplit('-',1)[-1])

    @staticmethod
    def ByName(name, *servername):
        dc = servername[0] if len(servername) > 0 else win32net.NetGetAnyDCName()
        try:
            res = win32net.NetUserGetInfo(dc,name,4)
            if res['logon_server'] == '\\\\*':
                res['logon_server'] = dc
        except:
            res = win32net.NetUserGetInfo(None,name,4)
            if res['logon_server'] == '\\\\*':
                res['logon_server'] = None
        try:
            sid,domain,sidtype = win32security.LookupAccountName(res['logon_server'], name)
        except:
            sid,domain,sidtype = win32security.LookupAccountName(None, name)
        assert sid == res.setdefault('user_sid',sid)

        if sidtype == win32security.SidTypeAlias:
            res['logon_domain'] = None if domain == 'BUILTIN' else domain
        else:
            assert domain == res.setdefault('logon_domain', domain)
        res['user_sid'] = win32security.ConvertSidToStringSid(res['user_sid'])
        res['type'] = sidtype
        return res

    @staticmethod
    def Profile(user):
        try:
            profile = win32com.client.GetObject(r'WinMgmts:\\.\root\cimv2:Win32_UserProfile.SID="%s"'%user['user_sid'])
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
    try:
        user = Query.ByName(name)
    except:
        raise KeyError, name
    gid,profile = Query.Gid(user),Query.Profile(user)
    return struct_passwd((user['name'], '*' if user.get('password',None) is None else user['password'], int(user['user_sid'].rsplit('-',1)[-1]), gid, user.get('comment',''), profile, os.environ['COMSPEC'].replace('\\', '/')))

def getpwuid(uid):
    for user in Query.All():
        if uid != int(user['user_sid'].rsplit('-',1)[-1]):
            continue
        gid,profile = Query.Gid(user),Query.Profile(user)
        return struct_passwd((user['name'], '*' if user.get('password',None) is None else user['password'], int(user['user_sid'].rsplit('-',1)[-1]), gid, user.get('comment',''), profile, os.environ['COMSPEC'].replace('\\', '/')))
    raise KeyError, uid

def getpwall():
    result = []
    for user in Query.All():
        gid,profile = Query.Gid(user),Query.Profile(user)
        result.append( struct_passwd((user['name'], '*' if user.get('password',None) is None else user['password'], int(user['user_sid'].rsplit('-',1)[-1]), gid, user.get('comment',''), profile, os.environ['COMSPEC'].replace('\\', '/'))))
    return result

