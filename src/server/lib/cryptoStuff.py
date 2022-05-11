import logging

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF, scrypt
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from lib.constants import get_base_folder

basepath = get_base_folder() / 'crypto_key'

logger = logging.getLogger(__name__)


def decryptLoginRequestETK(etk: bytes) -> bytes:
    path = basepath / 'private_key.pem'
    key = RSA.importKey(open(path, 'rt').read())
    cipher = PKCS1_OAEP.new(key)
    tk = cipher.decrypt(etk)
    return tk


def decryptMessage(epdmac: bytes, header: bytes, tk: bytes) -> bytes:
    """
    A method to decrypt EPD part of a received message

    ...

    Arguments
    ---------


    """
    logger.debug('decrypt started')
    nonce = header[6: 8] + header[8:14]
    epd = epdmac[:-12]
    mac = epdmac[-12:]
    payload = None
    try:
        cipher = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len=12)
        cipher.update(header)
        payload = cipher.decrypt_and_verify(epd, mac)
    except Exception as e:
        logger.warning(f'mac:{mac.hex()}\n'
                       f'nonce: {nonce.hex()}')
        logger.error(e)
        raise e

    return payload


def encryptMessage(payload: bytes, header: bytes, tk: bytes) -> tuple[bytes, bytes]:
    nonce = header[6:8] + header[8:14]
    cipehr = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len=12)
    cipehr.update(header)
    epd, tag = cipehr.encrypt_and_digest(payload)
    return (epd, tag)


def loginFunction(username: str, password: str) -> bool:
    usr_dic = {}
    path = basepath / 'users.passwd'
    with open(path, 'rt') as f:
        lines = f.readlines()
        for l in lines:
            l = l.split('\t')
            usr_dic[l[0]] = {'password': bytes.fromhex(
                l[1]), 'salt': bytes.fromhex(l[2])}
    salt = bytes(0)
    origi_password = bytes(0)
    if username in usr_dic:
        salt = usr_dic[username]['salt']
        origi_password = usr_dic[username]['password']
    else:
        salt = get_random_bytes(16)
        origi_password = bytes(10)

    pwHash = scrypt(bytes(password, 'utf-8'), salt, 128, 2**14, 8, 1)

    return pwHash == origi_password


def getHash(content: bytes) -> str:
    return SHA256.new(content).hexdigest()


def getFileHash(path: str) -> str:
    with open(path, 'rb') as f:
        data = f.read()
        return SHA256.new(data).hexdigest()


def deriveTransferKey(final_transfer_key: bytes, message_hash: bytes):
    transferKey = HKDF(final_transfer_key, 32, message_hash, SHA256)
    return transferKey
