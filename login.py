import json
import requests
import time
import re
import hmac
import hashlib
import math

username = ""
password = ""
srun_host = "gw.buaa.edu.cn"
host_ip = "10.200.21.4"
init_url = "https://{}".format(srun_host)
get_ip_api = "https://{}/cgi-bin/rad_user_info?callback=JQuery".format(srun_host)
get_ip_api_ip = "https://{}/cgi-bin/rad_user_info?callback=JQuery".format(host_ip)
get_challenge_api = "https://{}/cgi-bin/get_challenge".format(srun_host)
get_challenge_api_ip = "https://{}/cgi-bin/get_challenge".format(host_ip)
srun_portal_api = "https://{}/cgi-bin/srun_portal".format(srun_host)
srun_portal_api_ip = "https://{}/cgi-bin/srun_portal".format(host_ip)
rad_user_dm_api = "https://{}/cgi-bin/rad_user_dm".format(srun_host)
rad_user_dm_api_ip = "https://{}/cgi-bin/rad_user_dm".format(host_ip)
header = {
    "Host": srun_host,
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
}
n = "200"
type = "1"
ac_id = "1"
enc = "srun_bx1"
_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"


def init_getip():
    res = requests.get(get_ip_api)
    # [7:-1]是为了去掉前面的 jQuery( 和后面的 )
    data = json.loads(res.text[7:-1])
    ip = data.get("client_ip") or data.get("online_ip")
    return ip


def get_info(ip):
    info_temp = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": ac_id,
        "enc_ver": enc,
    }
    i = re.sub("'", '"', str(info_temp))
    i = re.sub(" ", "", i)
    return i


def get_base64(s):
    r = []
    x = len(s) % 3
    if x:
        s = s + "\0" * (3 - x)
    for i in range(0, len(s), 3):
        d = s[i : i + 3]
        a = ord(d[0]) << 16 | ord(d[1]) << 8 | ord(d[2])
        r.append(_ALPHA[a >> 18])
        r.append(_ALPHA[a >> 12 & 63])
        r.append(_ALPHA[a >> 6 & 63])
        r.append(_ALPHA[a & 63])
    if x == 1:
        r[-1] = "="
        r[-2] = "="
    if x == 2:
        r[-1] = "="
    return "".join(r)


def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i)
            | ordat(msg, i + 1) << 8
            | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24
        )
    if key:
        pwd.append(l)
    return pwd


def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(0, l):
        msg[i] = (
            chr(msg[i] & 0xFF)
            + chr(msg[i] >> 8 & 0xFF)
            + chr(msg[i] >> 16 & 0xFF)
            + chr(msg[i] >> 24 & 0xFF)
        )
    if key:
        return "".join(msg)[0:ll]
    return "".join(msg)


def get_xencode(msg, key):
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)


def get_token(ip):
    get_challenge_params = {
        "callback": "jQuery112404953340710317169_" + str(int(time.time() * 1000)),
        "username": username,
        "ip": ip,
        "_": int(time.time() * 1000),
    }
    test = requests.Session()
    get_challenge_res = test.get(
        get_challenge_api, params=get_challenge_params, headers=header
    )
    token = re.search('"challenge":"(.*?)"', get_challenge_res.text).group(1)
    return token


def get_md5(token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()


def get_chksum(token, hmd5, ip, i):
    chkstr = token + username
    chkstr += token + hmd5
    chkstr += token + ac_id
    chkstr += token + ip
    chkstr += token + n
    chkstr += token + type
    chkstr += token + i
    return chkstr


def do_complex_work(ip, token):
    i = get_info(ip)
    i = "{SRBX1}" + get_base64(get_xencode(i, token))
    hmd5 = get_md5(token)
    chksum = get_sha1(get_chksum(token, hmd5, ip, i))
    return i, hmd5, chksum


def is_connected():
    try:
        try:
            res = requests.get(get_ip_api)
        except:
            res = requests.get(get_ip_api_ip, headers=header, verify=False)
        data = json.loads(res.text[res.text.find("(") + 1 : -1])
        if "error" in data and data["error"] == "not_online_error":
            return True, False, data
        else:
            return True, True, data
    except:
        return False, False, None


def login():
    ip = init_getip()
    token = get_token(ip)
    i, hmd5, chksum = do_complex_work(ip, token)
    srun_portal_params = {
        "callback": "jQuery11240645308969735664_" + str(int(time.time() * 1000)),
        "action": "login",
        "username": username,
        "password": "{MD5}" + hmd5,
        "ac_id": ac_id,
        "ip": ip,
        "chksum": chksum,
        "info": i,
        "n": n,
        "type": type,
        "os": "windows+10",
        "name": "windows",
        "double_stack": "0",
        "_": int(time.time() * 1000),
    }
    test = requests.Session()
    try:
        srun_portal_res = test.get(
            srun_portal_api, params=srun_portal_params, headers=header
        )
    except:
        srun_portal_res = test.get(
            srun_portal_api_ip,
            params=srun_portal_params,
            headers=header,
            verify=False,
        )
    srun_portal_res = srun_portal_res.text
    data = json.loads(srun_portal_res[srun_portal_res.find("(") + 1 : -1])
    return data.get("error") == "ok"


if __name__ == "__main__":
    is_available, is_online, data = is_connected()
    if is_available and not is_online:
        login()
