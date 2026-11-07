
import hashlib
import hmac
import json
import os
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = bytes.fromhex('a7976d15')
PSK = 'm8WpkWhwxHKupYgSECIeII/tjIKZC06eexN2H9AvVDhJY2aH/4M6n94+4IN8XNoJ78s7fIHhtuYQE4QDKg1KTg=='
KEY = hashlib.sha512(PSK.encode()).digest()[:32]
FIELDS = ('Id','Sk','BundleId','Version','ClientVersion','ChargeMode','SimpleDeviceId',
          'CountryCode','TimeZoneName','Language','CurrentAuthSk','DeviceModel','AnalyticsId')

def compress_v2(data, enabled=True):
    # compressV2 @ 0x11b7970: <=40 bytes always raw; compress only if shorter.
    if enabled and len(data) > 40:
        compressed = zlib.compress(data)
        if len(compressed) < len(data):
            return b'\x01' + compressed
    return b'\x00' + data

def uncompress_v2(data):
    if not data:
        raise ValueError('missing compression marker')
    # Native decoder treats any nonzero byte as compressed.
    return zlib.decompress(data[1:]) if data[0] else data[1:]

def ctr(data, key, iv):
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return enc.update(data) + enc.finalize()

def encode(data, *, key=KEY, magic=MAGIC, compress=True, iv=None):
    iv = os.urandom(16) if iv is None else iv
    if len(iv) != 16 or len(key) != 32 or len(magic) != 4:
        raise ValueError('invalid IV/key/magic length')
    return iv + ctr(compress_v2(data, compress) + magic, key, iv)

def decode(blob, *, key=KEY, magic=MAGIC):
    if len(blob) < 21:
        raise ValueError('input shorter than minimum V2 frame')
    plain = ctr(blob[16:], key, blob[:16])
    if not hmac.compare_digest(plain[-4:], magic):
        raise ValueError('magic mismatch')
    return uncompress_v2(plain[:-4])

def login_message(context, username, password):
    # Zero-valued fields are omitted by generated native marshaler.
    ctx = {k: context[k] for k in FIELDS if k in context and context[k] not in ('',0,None)}
    req = {k:v for k,v in [('Username',username),('Password',password)] if v}
    body = json.dumps({'Ctx':ctx,'Req':req},ensure_ascii=False,separators=(',',':')).encode()
    method = b'UserLoginWithUsername'
    return bytes([len(method)]) + method + body

def parse_rpc_frame(data):
    if not data:
        raise ValueError('missing RPC status byte')
    if data[0] == 1:
        raise ValueError('RPC transport error: ' + data[1:].decode('utf-8','replace'))
    if data[0] != 2:
        raise ValueError('unknown RPC status byte: ' + str(data[0]))
    return json.loads(data[1:])  # response envelope has Out / RpcErr, not Data / Code

if __name__ == '__main__':
    # Synthetic values only. Local tests do not prove interoperability.
    for data in (b'', b'abc', b'a'*40, b'a'*41, bytes(range(256)), b'hello'*100):
        for compressed in (True, False):
            frame = encode(data, compress=compressed, iv=bytes(range(16)))
            assert decode(frame) == data
    assert compress_v2(b'abc') == b'\x00abc'
    assert compress_v2(b'a'*41)[0] == 1
    assert compress_v2(bytes(range(256)))[0] == 0
    assert parse_rpc_frame(b'\x02{"Out":{},"RpcErr":null}')['RpcErr'] is None
    damaged=bytearray(encode(b'abc'));damaged[-1]^=1
    try:
        decode(bytes(damaged))
        raise AssertionError('corruption accepted')
    except ValueError:
        pass
    print('Offline codec tests passed. No network requests sent.')
