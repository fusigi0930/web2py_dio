import json
import time
import base64
import sys
#import gluon.contrib.pyaes as AES
from Crypto.Cipher import AES
if sys.version_info[0] == 3:
    from Crypto.Util.Padding import pad
from gmpy2 import invert
from gmpy2 import mul
from gmpy2 import powmod
import struct
from datetime import datetime
from datetime import timedelta

import binascii
import urllib

rsa_key64_d = '553c08eb31076701'
rsa_key64_n = 'a7a09ab034348f91'
rsa_key64_e = '10001' # 65537

err_9999 = '9999: fatal error for user info'
err_9998 = '9998: exception for process: '
err_1001 = '1001: no code'

err_2001 = '2001: user not activated!'
err_2002 = '2002: s expired'
err_2003 = '2003: t expired'

ok_0000 = '0000: {}'

def pri_decode64(endata):
    ret = b''
    if sys.version_info[0] == 2:
        key_d = long(rsa_key64_d, 16)
        key_n = long(rsa_key64_n, 16)
        for i in range(0, len(endata), 8):
            splitdata = endata[i:i+8]
            data = struct.unpack("<Q", splitdata)[0]
            ret += struct.pack("<Q", long(powmod(data, key_d, key_n)))
    elif sys.version_info[0] == 3:
        key_d = int(rsa_key64_d, 16)
        key_n = int(rsa_key64_n, 16)
        for i in range(0, len(endata), 8):
            splitdata = endata[i:i+8]
            data = struct.unpack("<Q", splitdata)[0]
            ret += struct.pack("<Q", int(powmod(data, key_d, key_n)))

    return ret

def pri_encode64(endata):
    ret = b''
    if sys.version_info[0] == 2:
        key_d = long(rsa_key64_d, 16)
        key_n = long(rsa_key64_n, 16)
        for i in range(0, len(endata), 8):
            splitdata = endata[i:i+8]
            data = struct.unpack("<Q", splitdata)[0]
            ret += struct.pack("<Q", long(powmod(data, key_d, key_n)))
    elif sys.version_info[0] == 3:
        key_d = int(rsa_key64_d, 16)
        key_n = int(rsa_key64_n, 16)
        for i in range(0, len(endata), 8):
            splitdata = endata[i:i+8]
            data = struct.unpack("<Q", splitdata)[0]
            ret += struct.pack("<Q", int(powmod(data, key_d, key_n)))

    return ret

def pkcs7pad(data):
    data_len = len(data)
    append_size = AES.block_size - data_len % AES.block_size
    padd_data = chr(append_size) * append_size

    return data+padd_data

def result_pack(key, result):
    ret = {}
    realkey = b'\x07orzQ_Q\x08'

    if sys.version_info[0] == 3:
        if key != None:
            if type(key) is str:
                realkey = realkey + bytes(key, encoding='utf-8')
            elif type(key) is bytes:
                realkey = realkey + key
    elif sys.version_info[0] == 2:
        if key != None:
            realkey = bytearray(realkey+key)

    if result == None or result == '':
        result = err_9998

    rsakey = pri_encode64(realkey)

    iv = 16 * b'\x00'
    if sys.version_info[0] == 3:
        cryptor = AES.new(realkey, AES.MODE_CBC, iv)
        outdata = cryptor.encrypt(pad(bytes(result, encoding='utf-8'), AES.block_size))
    elif sys.version_info[0] == 2:
        cryptor = AES.new(str(realkey), AES.MODE_CBC, iv)
        padded = pkcs7pad(bytes(result))
        outdata = cryptor.encrypt(str(padded))

    if sys.version_info[0] == 2:
        ret['vcode'] = urllib.quote_plus(base64.b64encode(rsakey))
        ret['vvalue'] = urllib.quote_plus(base64.b64encode(outdata))
    elif sys.version_info[0] == 3:
        ret['vcode'] = urllib.parse.quote_plus(base64.b64encode(rsakey))
        ret['vvalue'] = urllib.parse.quote_plus(base64.b64encode(outdata))

    return json.dumps(ret)

# -*- coding: utf-8 -*-
### required - do no delete
def user(): 
    return dict(form=auth())
### end requires
def error():
    return dict()

def reg_user():
    if auth.is_logged_in():
        auth.logout()
    auth.settings.register_next = URL('api', 'register', vars=dict(msg='ok'))
    return dict(form=auth.register(next = auth.settings.register_next))

auth.settings.allow_basic_login = True
auth.settings.actions_disabled.append('register')
auth.settings.login_url = URL('api', 'user/login')
@auth.requires_login()
def pin():
    # json.dumps(request.vars) to get all http GET request'
    now_time = datetime.now()
    ustatus_info = db(db.t_user_status.f_user_id == auth.user.id).select().first()

    if ustatus_info == None:
        return result_pack(None, err_9999)
    
    if ustatus_info.f_status == 0:
        return result_pack(None, err_2001)
    elif ustatus_info.f_status == 2:
        return result_pack(None, err_2002)
    
    if ustatus_info.f_expire_time < now_time and ustatus_info.f_status != 100:
        ustatus_info.f_status = 2
        ustatus_info.update_record()
        return result_pack(None, err_2003)

    verify_code = request.vars['vcode']
    if verify_code == None or verify_code == '':
        return result_pack(None, err_1001)

    un_b64data = base64.b64decode(verify_code)
    dersa = pri_decode64(un_b64data)
    #return binascii.hexlify(dersa)
    return result_pack(dersa, ok_0000.format('go works'))

def register():
    msg = ""
    user_group = db(db.auth_group.role == 'user').select().first()
    db(db.auth_group.role == 'user_{}'.format(auth.user.id)).delete()

    db.auth_membership.update_or_insert(db.auth_membership.user_id == auth.user.id, user_id = auth.user.id, group_id = user_group)

    now_time = datetime.now()
    db.t_user_status.update_or_insert(db.t_user_status.f_user_id == auth.user.id, f_user_id = auth.user.id, f_status = 0, f_expire_time = now_time + timedelta(days=30) )

    return dict(msg = 'user: {} {} ({}) register completed'.format(auth.user.first_name, auth.user.last_name, auth.user.email))
