import Crypto.PublicKey.RSA
import Crypto.Cipher.PKCS1_OAEP
import Crypto.Random
import Crypto.Cipher.AES
import Crypto.Hash.SHA512
import argon2
import argon2.exceptions
import json


def generateRSAKeyPair() -> (
        Crypto.PublicKey.RSA.RsaKey,
        Crypto.PublicKey.RSA.RsaKey):  # Generates a random public/private key pair for use in RSA
    key = Crypto.PublicKey.RSA.generate(2048)
    publicKey = key.public_key()
    return key, publicKey


def readRSAKeyFromFile(filename: str) -> Crypto.PublicKey.RSA.RsaKey:  # Reads an RSA key from a file
    fileStream = open(filename, "r")
    key = Crypto.PublicKey.RSA.import_key(fileStream.read())
    fileStream.close()
    return key


def readRSAKeyFromText(text: str) -> Crypto.PublicKey.RSA.RsaKey:  # Reads an RSA key from a string
    key = Crypto.PublicKey.RSA.import_key(text)
    return key


def writeRSAKey(filename: str, key: Crypto.PublicKey.RSA.RsaKey):  # Writes an RSA key to a file
    fileStream = open(filename, "wb")
    fileStream.write(key.export_key("PEM"))
    fileStream.close()


def encryptDataRSA(publicKey: Crypto.PublicKey.RSA.RsaKey,
                   data: bytes) -> bytes:  # Encrypts data with an RSA public key
    cipher = Crypto.Cipher.PKCS1_OAEP.new(publicKey)
    encrypted = cipher.encrypt(data)
    return encrypted


def decryptDataRSA(privateKey: Crypto.PublicKey.RSA.RsaKey,
                   encrypted: bytes) -> bytes:  # Decrypts data with an RSA private key
    cipher = Crypto.Cipher.PKCS1_OAEP.new(privateKey)
    originalData = cipher.decrypt(encrypted)
    return originalData


def generateKey() -> bytes:  # Generates a random key
    key = Crypto.Random.get_random_bytes(32)
    return key


def generateAESCipher(key: bytes, nonce: bytes = None) -> Crypto.Cipher.AES:  # Generates an AES cipher from a key
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_GCM, nonce=nonce)
    return cipher


def encryptDataAES(data: bytes, key: bytes) -> (bytes, bytes, bytes):  # Encrypts some data with AES
    cipher = generateAESCipher(key)
    encrypted, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, encrypted, tag


def decryptDataAES(key: bytes, encrypted: bytes, nonce: bytes, tag: bytes) -> bytes:  # Decrypts some data with AES
    cipher = generateAESCipher(key, nonce)
    plaintext = cipher.decrypt_and_verify(encrypted, tag)
    return plaintext


def hashStringWithSHA(string: str, salt: bytes = b'') -> str:
    data = string.encode("utf-8")
    if len(salt) != 32 and salt != b"":
        raise TypeError("The salt should be 32 bytes long.")
    if salt == b'':  # If the salt isn't given,
        salt = Crypto.Random.get_random_bytes(32)  # Generates 32 random bytes for a salt
    hashingFunction = Crypto.Hash.SHA512.new()
    hashingFunction.update(salt + data)
    hashedData = hashingFunction.hexdigest()
    return salt.hex() + ":" + hashedData  # Gives the hash in the form salt:hash


def hashStringWithArgon(string: str) -> str:
    hashingAlgorithm = argon2.PasswordHasher(salt_len=32)  # Creates a new hashing class with a salt of 32 bytes
    return hashingAlgorithm.hash(string)  # Hash the string


def verifyHashWithArgon(hashed: str, password: str) -> bool:
    hashingAlgorithm = argon2.PasswordHasher(salt_len=32)  # Specifies a 32 byte salt length
    try:
        hashingAlgorithm.verify(hashed, password)  # Verifies the hash
        return True  # If this succeeds, return true
    except argon2.exceptions.InvalidHash:  # If the verification fails,
        return False  # Return false


def readAESKey(filename: str) -> bytes:  # Reads an AES key from a file
    with open(filename, "rb") as file:
        AESKey = file.read()
    return AESKey


def writeAESKey(filename: str, AESKey: bytes):  # Writes an AES key from a file
    with open(filename, "wb") as file:
        file.write(AESKey)


def writeEncryptedJSON(filename: str, AESKey: bytes, JSONData: dict):  # Saves a dictionary to an encrypted json file
    plaintext = json.dumps(JSONData)
    nonce, ciphertext, tag = encryptDataAES(plaintext.encode("utf-8"), AESKey)
    with open(filename, "wb") as file:
        file.write(nonce)
        file.write(tag)
        file.write(ciphertext)


def readEncryptedJSON(filename: str, AESKey: bytes) -> dict:  # Gets a dictionary from an encrypted json file
    with open(filename, "rb") as file:
        allData = file.read()
    nonce = allData[:16]
    tag = allData[16:32]
    ciphertext = allData[32:]
    plaintext = decryptDataAES(AESKey, ciphertext, nonce, tag).decode("utf-8")
    jsonData = json.loads(plaintext)
    return jsonData
