# MITRE eCTF 2025 Morgan State Write Up
## Forging Morgan State's Subscriptions 
#### Overview
A cryptographic oracle allowed us to forge subscriptions with custom parameters, which allowed us to modify existing subscriptions and get three attack scenarios (expired, pirated, and recording)

### Statement of Problem
In Morgan State's design, each subscription contains the symmetric ChaCha20-Poly1305 keys that will be used to encrypt/decrypt frame data for each of the channels.  In addition, there is another key, referred to as the system key, that is used to encrypt/decrypt the entire frame packet (including the metadata like timestamp and channel number) as well as the subscriptions.  This key is kept on the decoder from the factory.

In order to decrypt frames that we did not have valid subscriptions for we would have needed to do one of the following:
1. Get a subscription with custom parameters onto the board.
1. Extract the channel key from the board and the system key to decrypt frames manually.

### Overview of Morgan State's Design
Their main encryption scheme was ChaCha20-Poly1305, a symmetric stream cipher with authentication checking.  But you will soon find out later, the Poly1305, the authentication checking algorithm, was not used at all, including the AAD.

#### Encoder/Decoder
The encoding algorithm for non-emergency channels worked as such:
Given the `channel`, the plaintext `frame`, and the `timestamp`:
1. Generate a nonce, `n1`.
2. Calculate the length of `frame`, `l1`, as a `uint32_t`.
3. Encrypt the `frame` using a shared symmetric key for only that channel (`CHANKEY`), and `n1` without any additional data to obtain the tag, `tag1`, and ciphertext, `ct1`.
4. Calculate the length of `tag1 + n1 + l1 + frame + ct1 + l2`, as a `uint32_t`.
5. Calculate the SHA-256 hash of: `tag1 + n1 + len(ct1) + channel + timestamp + ct1`, `hash`.
6. Generate a nonce, `n2`.
7. Encrypt the packet, `tag1 + n1 + l1 + channel + timestamp + ct1` (same as step 4), to get the ciphertext, `ct2`, and tag, `tag2`, using a symmetric key, `SYSKEY` that is used for all channels.
8. Send `tag2 + hash + n2 + l2 + ct2` to the decoder.  The sent frames should look like the following.
```
  16 bytes       32 bytes        12 bytes    4 bytes    Variable Length
    `tag`          `hash`          `n2`       `l2`            `ct2`
+-----------+----------------+-------------+--------+---------------------+
|           |      Plain     |             | Length |                     |
|    Tag    |      Text      |    Nonce    |   of   |      Ciphertext     |
|           |    Checksum    |             | Cipher |                     |
+-----------+----------------+-------------+--------+---------------------+
```

On the decoder, the following steps take place:
1. `ciphertext2` is decoded using `SYSKEY` and `n2` to get the corresponding plaintext.
1. The plaintext is hashed using SHA-256 to get `hashout`.
1. `hashout` is compared to `hash` that was sent.
    1. If they do not match, `Bad Hash Data` is sent over UART as an error.
    1. Otherwise, frame is then decrypted using the `CHANKEY` and processed like normal, including checking if there is a valid subscription to the channel the frame was meant for.

*At no point in this process is the Poly1305 tag checked*

#### Subscriptions
The subscriptions were generated as such:
Given a `channel`, `start`, `end`, and `device_id`:
1. The plaintext is constructed as `device_id + start + end + channel + channel key`
1. The SHA-256 hash of the plaintext is computed.
1. A nonce is generated.
1. The plaintext is encrypted with the nonce to create the ciphertext and tag.
1. The size of the subscription is computed (it is always 56 bytes).
1. `tag + hash + nonce + size + ciphertext` is written to a file.  The subscription file should be laid out as the following
```
|------------- Unencrypted -------------|--------------------------- Encrypted ----------------------------|
  16 bytes    32 bytes   12 bytes 4 bytes 4 bytes   8 bytes     8 bytes    4 bytes         32 bytes
+---------+--------------+-------+------+--------+-----------+-----------+---------+-----------------------+
|         |              |       |      | Device |           |           |         |                       |
|   Tag   |   Checksum   | Nonce | Size |   ID   |   Start   |    End    | Channel |      Channel Key      | 
|         |              |       |      |        |           |           |         |                       |
+---------+--------------+-------+------+--------+-----------+-----------+---------+-----------------------+
```
On the decoder, the following steps take place:
1. The ciphertext is decrypted using the `SYSKEY` and nonce.
1. The SHA-256 hash of the decrypted ciphertext is computed.
1. If the computed hash is compared to the sent checksum.
    1. If they do not match, `Bad Hash Data` is sent over UART as an error.
1. Otherwise, the decoder_id of the packet is checked against the decoder's actual ID
    1. If they do not match, `Bad Decoder` is sent over UART as an error.
1. Otherwise, the subscription is loaded onto the decoder and will be used to decrypt frames that are for that subscription.

### The Vulnerability
In this case, we can see that the `Bad Hash Data` is an oracle that would allow us to see if our decrypted ciphertext matched the plaintext.  If the hashes don't match, then our plaintext could not equal the decrypted ciphertext, otherwise, we must have guessed the correct ciphertext/plaintext - except in the extremely rare case of a hash collision, which is so low we do not have to worry about it.  This would allow us to forge/decrypt anything with the `SYSKEY`.

#### Background
An oracle is a feedback mechanism, usually a message from the victim, that leaks some sort of information that allows us to accomplish a goal, usually incrementally.  If we were playing a game where we guess a number where I give the feedback of "higher" or "lower".  The "higher" or "lower" would be the oracle that allows us to eventually guess the correct number.

#### In Depth Explanation of the Hash Attack
Because we can control the hash and the ciphertext, we can leverage the oracle to perform an oracle attack that I will refer to as a "hash attack."  We take advantage of the fact that ChaCha20 is a stream cipher to incrementally (byte by byte) forge/decrypt in a much shorter time than brute forcing.  For each byte, we send the previous bytes plus our guess and the hash of our guess.  This is similar to the guessing game before, but each byte is a separate number have to guess.  The methods for forging and decrypting are similar, but slightly different.

#### Hash Attack Forging
Given a 16 byte plaintext, we would do the following.
1. Start with an empty array of bytes, `ciphertext`.
1. Create a copy of `ciphertext` called `guess`, and append `0x00` to the end of it.
1. Compute the SHA-256 hash of your plaintext, up to the length of `guess`, i.e., substring from 0 to `len(guess)`.
1. Send the checksum, `guess`, and a 12-byte constant nonce, (could be all zeros, just make sure it stays the same).
1. If we get the `Bad Hash Data` message back, go back to step 2 and try with `0x01`, `0x02`, `0x03`, ... until we no longer get the `Bad Hash Data` message.
1. Once the hash succeeds, set `ciphertext` equal to your `guess` array, then start over from step 2 until your `ciphertext` array is the same length as the plaintext.
1. You are have now forged a ciphertext nonce pair that, when decrypted with `SYSKEY`, will get you the plaintext. 

#### Hash Attack Decryption
Given a 16 byte ciphertext and nonce, we would do the following.
1. Start with an empty array of bytes, `plaintext`.
1. Create a copy of your array, called `guess`, and append `0x00` to it.
1. Compute the SHA-256 hash of `guess`.
1. Send the checksum, nonce, and first byte of the ciphertext.
1. If we get the `Bad Hash Data` message back, go back to step 2 and try with `0x01`, `0x02`, `0x03`, ... until we no longer get the `Bad Hash Data` message.
1. Once the hash succeeds, set `plaintext` equal to your `guess` array, then start over from step 2 until your `plaintext` array is the same length as your the ciphertext. 

This snippet highlights the vulnerable code.
#### Code Snippet From `decoder.c` Inside of the `decode` Function
```c
// ---- SNIP ----
decrypt_sym(new_frame->ciphertext,
            new_frame->cipher_len,
            syskey,
            new_frame->Nonce,
            new_frame->tag,
            pt);  // auth decrypthion
hash(pt, sizeof(pt), hashout);
    
if (compare(hashout,new_frame->Hash,sizeof(hashout))) {
    sprintf(output_buf, "Bad Hash Data");
    print_error(output_buf);
    return -1;
} else {
    comp_chck = 1;
}
// ---- SNIP ----
```
(A similar code snippet exists the subscription checking, but because we don't want successful decryptions to fill up our subscription limits with garbage (only 8), we chose to use the `decode` function.

Essentially, this oracle allows us to check, for each byte at a time, if our plaintext/ciphertext was correct, reducing the total possible number of combinations to 256 * N, where N is the length of the plaintext/ciphertext (scales linearly with length).

In the context of this attack, we would need to create a plaintext subscription packet, forge it into a ciphertext using the hash attack, then send it to the decoder to be decrypted.

### The Exploit
#### Creating an Oracle Function
In order to start our exploit, we need to create an oracle function that allows us to see if a ciphertext and nonce pair decrypted to a plaintext:
```python
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
```
The script works by creating a frame packet using the nonce, the computed hash of the plaintext, and the ciphertext, then sending it to the decoder to be decoded.  Recall that the decoder will use the `SYSKEY` to decrypt the ciphertext then check if the hash matched.  When `DecoderError` exception is thrown by the decoder interface, we check if it contains the string `Bad Hash Data`.  If it does, then we know the hashes did not match, and therefor, the ciphertext and nonce did not decrypt to the plaintext.

#### Decrypting Subscriptions to Get the Channel Key
In order to modify parts of a subscription, we first need to get the channel key.  This was done by performing our hash attack to decrypt the encrypted part of our subscriptions, which contain the channel key we need.
```python
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
```
This script works exactly as described in the Hash Attack Decryption section and will get us the decrypted subscription.  The final 32 bytes of the plaintext will contain the channel key.

#### Forging Custom Subscriptions Containing the Channel Key
In order to create forged subscriptions, we need to create a function that will forge any plaintext to a ciphertext encrypted with the `SYSKEY`.
```python
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
```
The script follows the same process as described in the Hash Attack Forging section.

### Putting It All Together
These three functions are used in combination for our attack.  The following steps were taken to forge a subscription with modified metadata to fit our needs:
1. Load the subscription we wished to modify
1. Extract the nonce from bytes 48 to 60.
1. Run `hash_attack_decrypt` with the victim interface, this nonce, and bytes 64 to the end of the subscription as the ciphertext.
1. Extract the last 32 bytes of the decrypted ciphertext to get the channel key.
1. Extract the channel number from the 4 before the channel key.
1. Construct a plaintext subscription by concatenating our device id (`0xf870d9c5`), start time (`0`), end time (`2**64-1`, the max), channel number, and channel key.
1. Run `hash_attack_forge` with the victim interface, any nonce, and our plaintext subscription.
1. Write the subscription to a file, or flash it directly onto the victim device.

### Side Notes
#### Why Forge Subscriptions If We Have the Channel Key
We chose to forge subscriptions instead of decrypting the frame packets manually because the process of decrypting an entire frame packet would have taken longer than forging a subscription.  Because we don't have the `SYSKEY`, we would have had to repeat the hash attack on each frame packet then decrypt the frame encrypted with the channel key.
#### Device ID and Decoder ID
Device ID and Decoder ID are used interchangeably and mean exactly the same thing.  The Morgan State codebase uses both terms, so we used it in contexts where they used it in order to make reviewing their source code easier.
