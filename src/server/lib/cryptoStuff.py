from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

def decryptLoginRequestETK(etk: bytes) -> bytes:
    key = RSA.importKey(open('private_key.pem').read())
    cipher = PKCS1_OAEP.new(key)
    tk = cipher.decrypt(etk)
    return tk


def decryptLoginRequestEPD(epdmac: bytes, header:bytes, tk: bytes, rnd: bytes, sqn: bytes) -> bytes:
    """
    A method to decrypt EPD part of a received message

    ...
    
    Arguments
    ---------

    
    """
    nonce = sqn + rnd
    epd = epdmac[:-12]
    mac = epdmac[-12:]
    cipher = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len=len(mac))
    cipher.update(header)
    payload = cipher.decrypt_and_verify(epd, mac)
    return payload
