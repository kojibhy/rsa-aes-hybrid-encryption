import base64
import hashlib
import typing

from Cryptodome import Random
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes

StringOrBytes = typing.TypeVar('StringOrBytes', str, bytes)  # Must be str or bytes


class BaseCipher:
    block_size: int = 128

    @staticmethod
    def str_to_bytes(value: [str, bytes]) -> bytes:
        if isinstance(value, str):
            return value.encode(encoding='utf8')
        return value

    def _pad(self, s):
        return s + (self.block_size - len(s) % self.block_size) * BaseCipher.str_to_bytes(
            chr(self.block_size - len(s) % self.block_size))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


class AESCipher(BaseCipher):
    """AES is a variant of Rijndael which has a fixed block size of 128 bits,
    and a key size of 128, 192, or 256 bits."""

    def __init__(self, key, *args, **kwargs):
        self.session_key: bytes = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    def encrypt(self, plaintext: StringOrBytes) -> bytes:
        plaintext: bytes = self.str_to_bytes(plaintext)
        raw = self._pad(plaintext)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, ciphertext: StringOrBytes) -> bytes:
        """ decode all data to bytes """
        ciphertext: bytes = self.str_to_bytes(ciphertext)
        iv: bytes = ciphertext[:AES.block_size]
        cipher: AES = AES.new(self.session_key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(ciphertext[AES.block_size:]))

    def encrypt_b64(self, text: StringOrBytes, to_string=False) -> StringOrBytes:
        ciphertext = self.encrypt(text)
        if to_string:
            return base64.b64encode(ciphertext).decode()
        else:
            return base64.b64encode(ciphertext)

    def decrypt_b64(self, ciphertext: StringOrBytes, to_string=False) -> StringOrBytes:
        ciphertext: bytes = base64.b64decode(ciphertext)
        plaintext: bytes = self.decrypt(ciphertext)
        if to_string:
            return plaintext.decode()
        else:
            return plaintext


class RSACipher(BaseCipher):
    """RSA involves a public key and private key.
    The public key can be known to everyone; it is used to encrypt messages.
    Messages encrypted using the public key can only be decrypted with the private key."""

    def __init__(self, import_key):
        self.rsa_key_pair = RSA.import_key(import_key)
        super().__init__()

    @classmethod
    def generate(cls) -> RSA.RsaKey:
        return RSA.generate(2048)

    @classmethod
    def generate_keys(cls) -> typing.Tuple[str, str]:
        rsa_key = RSACipher.generate()
        rsa_public_key, rsa_private_key = rsa_key.publickey().export_key(), rsa_key.export_key()
        return rsa_public_key.decode(), rsa_private_key.decode()

    def encrypt(self, plaintext: StringOrBytes, session_key=None) -> typing.Tuple[bytes, bytes]:
        if not session_key:
            #   For instance, if you use RSA 2048 and SHA-256, the longest message
            #             you can encrypt is 190 byte long.
            session_key: bytes = get_random_bytes(128)

        session_key: bytes = self.str_to_bytes(session_key)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(
            self.rsa_key_pair
        )
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        aes = AESCipher(key=session_key)
        return enc_session_key, aes.encrypt(plaintext)

    def decrypt(self, ciphertext: StringOrBytes, session_key: StringOrBytes) -> bytes:
        # Decrypt the session key with the private RSA key
        session_key: bytes = self.str_to_bytes(session_key)

        cipher_rsa = PKCS1_OAEP.new(self.rsa_key_pair)
        session_key = cipher_rsa.decrypt(session_key)
        # Decrypt the data with the AES session key
        aes = AESCipher(key=session_key)
        return aes.decrypt(ciphertext)

    @staticmethod
    def hashed(plaintext: StringOrBytes) -> str:
        """:return sha1.hexdigest()"""
        if isinstance(plaintext, str):
            hashed = hashlib.sha1(plaintext.encode())
        else:
            hashed = hashlib.sha1(plaintext)
        return hashed.hexdigest()

    def encrypt_b64(self, plaintext: StringOrBytes,
                    session_key=None, to_string=False) -> typing.Dict[str, StringOrBytes]:

        hashed_value: str = self.hashed(plaintext)
        aes_session_key, ciphertext = self.encrypt(plaintext, session_key)

        if to_string:
            return dict(
                session_key=base64.b64encode(aes_session_key).decode(),
                cipher_text=base64.b64encode(ciphertext).decode(),
                hashed=hashed_value
            )
        else:
            return dict(
                session_key=base64.b64encode(aes_session_key),
                cipher_text=base64.b64encode(ciphertext),
                hashed=hashed_value.encode()
            )

    def decrypt_b64(self, ciphertext: StringOrBytes, session_key: StringOrBytes, to_string=False) -> StringOrBytes:
        session_key: bytes = base64.b64decode(session_key)
        ciphertext: bytes = base64.b64decode(ciphertext)

        plaintext: bytes = self.decrypt(ciphertext, session_key)

        if to_string:
            return plaintext.decode()
        else:
            return plaintext
