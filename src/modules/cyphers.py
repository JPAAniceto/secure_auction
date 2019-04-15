import base64
import secrets
import uuid
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as aPadding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# encrypt 'plainText' with public 'key' using RSA algorithm
def encrypt_assymetric(key, plainText):
    plainTextBytes = base64.b64encode(bytes(plainText, "utf-8"))

    cypherTextBytes = key.encrypt(
        plainTextBytes,
        aPadding.OAEP(
            mgf=aPadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return cypherTextBytes

# decrypt 'cypherText' with private 'key' using RSA algorithm
def decrypt_assymetric(key, cypherTextBytes):
    plaintextBytes = key.decrypt(
        cypherTextBytes,
        aPadding.OAEP(
            mgf=aPadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    plainText = base64.b64decode(plaintextBytes).decode('utf-8')

    return plainText

def generateSymKey(bytes=32):
    try:
        a = int(bytes)
        assert a == 16 or a >=32
    except:
        raise ValueError

    return secrets.token_bytes(int(bytes))

def encrypt_symmetric(key, plainTextBytes, algorithm = 'aes', mode = 'cbc'):
    # Get algorithm
    if algorithm.replace(' ', '').lower() in sym_algorithms:
        algorithm = sym_algorithms[algorithm.replace(' ', '').lower()]
    else:
        raise ValueError

    # Get mode
    if mode.replace(' ', '').lower() in sym_modes:
        mode = sym_modes[mode.replace(' ', '').lower()]
    else:
        raise ValueError

    iv = ''

    if algorithm is algorithms.SEED:
        if mode is modes.CTR:
            # Generate nonce
            iv = bytes(secrets.token_hex(int(len(key)/2)), "utf-8")
        else:
            # Generate iv
            iv = secrets.token_bytes(int(len(key)))
    else:   
        if mode is modes.CTR:
            # Generate nonce
            iv = bytes(secrets.token_hex(int(len(key)/4)), "utf-8")
        else:
            # Generate iv
            iv = secrets.token_bytes(int(len(key)/2))

    if mode is modes.CBC:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plainTextBytes)
        padded_data += padder.finalize()
        plainTextBytes = padded_data

    cipher = Cipher(algorithm(key), mode(iv), default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plainTextBytes) + encryptor.finalize()

    return ct + iv

def decrypt_symmetric(key, data, algorithm = 'aes', mode = 'cbc'):
    # Get algorithm
    if algorithm.replace(' ', '').lower() in sym_algorithms:
        algorithm = sym_algorithms[algorithm.replace(' ', '').lower()]
    else:
        raise ValueError

    # Get mode
    if mode.replace(' ', '').lower() in sym_modes:
        mode = sym_modes[mode.replace(' ', '').lower()]
    else:
        raise ValueError

    if algorithm is algorithms.SEED:
        iv = data[-int(len(key)):]
        data = data[:-int(len(key))]
    else:   
        iv = data[-int(len(key)/2):]
        data = data[:-int(len(key)/2)]

    cipher = Cipher(algorithm(key), mode(iv), default_backend())
    decryptor = cipher.decryptor()
    plaintextBytes = decryptor.update(data) + decryptor.finalize()

    if mode is modes.CBC:
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(plaintextBytes)
        unpadded_data += unpadder.finalize()
        plaintextBytes = unpadded_data

    return plaintextBytes

sym_algorithms = {
    'aes'       :   algorithms.AES,
    'camellia'  :   algorithms.Camellia,
    # 'chacha20'  :   algorithms.ChaCha20,
    'tripledes' :   algorithms.TripleDES,
    'cast5'     :   algorithms.CAST5,
    'seed'      :   algorithms.SEED
}

sym_modes = {
    'cbc'       :   modes.CBC,
    'ctr'       :   modes.CTR,
    'ofb'       :   modes.OFB,
    'cfb'       :   modes.CFB,
    'cfb8'      :   modes.CFB8,
    # 'gcm'       :   modes.GCM

}

if __name__ == '__main__':
    key = generateSymKey(32)
    plainText = 'Exemplo de teste'.encode('utf-8')
    data = encrypt_symmetric(key, plainText)
    plainTextDecoded = decrypt_symmetric(key, data)
    print(plainTextDecoded.decode('utf-8'))

    # not supported in default_backend():
    # encryptionAlg = 'camellia', encryptionMode = 'ctr' 
    # encryptionAlg = 'camellia', encryptionMode = 'cfb8'
    # encryptionAlg = 'tripledes', encryptionMode = 'ctr'
    # encryptionAlg = 'cast5', encryptionMode = 'ctr'
    # encryptionAlg = 'cast5', encryptionMode = 'cfb8'
    # encryptionAlg = 'seed', encryptionMode = 'ctr'
    # encryptionAlg = 'seed', encryptionMode = 'cfb8'

    # to many complications:
    # chacha20
    # gcm

    # 16 bytes key
    # algorithms.TripleDES
    # algorithms.CAST5
    # algorithms.SEED