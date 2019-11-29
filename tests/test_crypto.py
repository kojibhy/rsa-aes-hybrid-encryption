import hashlib
import random
import string
import time
import unittest

from Cryptodome.Random import get_random_bytes

from src.crypto import AESCipher, StringOrBytes, RSACipher

try:
    random = random.SystemRandom()
    using_sysrandom = True
except NotImplementedError:
    import warnings

    warnings.warn('A secure pseudo-random number generator is not available '
                  'on your system. Falling back to Mersenne Twister.')
    using_sysrandom = False


def random_string(length=12, allowed_chars=(string.ascii_lowercase
                                            + string.ascii_uppercase
                                            + string.digits
                                            + '!@#$%^&*(-_=+)')):
    """
    Return a securely generated random string.

    The default length of 12 with the a-z, A-Z, 0-9 character set returns
    a 71-bit value. log_2((26+26+10)^12) =~ 71 bits
    """
    if not using_sysrandom:
        # This is ugly, and a hack, but it makes things better than
        # the alternative of predictability. This re-seeds the PRNG
        # using a value that is hard for an attacker to predict, every
        # time a random string is required. This may change the
        # properties of the chosen random sequence slightly, but this
        # is better than absolute predictability.
        random.seed(
            hashlib.sha256(
                ('%s%s' % (random.getstate(), time.time())).encode()
            ).digest()
        )
    return ''.join(random.choice(allowed_chars) for i in range(length))

class TestCryptoAESHelper(unittest.TestCase):

    def setUp(self):
        self._test_string = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor ' \
                            'incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud ' \
                            'exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure ' \
                            'dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. ' \
                            'Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt ' \
                            'mollit anim id est laborum. '
        self._test_bytes_string = self._test_string.encode()

        self.session_key = get_random_bytes(128)

        self._aes = AESCipher(self.session_key)

    def test_text_as_string(self):
        # test options
        test_value: str = self._test_string
        expected_value: bytes = self._test_bytes_string
        # test case
        ciphertext: bytes = self._aes.encrypt(test_value)
        self.assertTrue(isinstance(ciphertext, bytes))
        plaintext: bytes = self._aes.decrypt(ciphertext)
        self.assertTrue(isinstance(plaintext, bytes))
        self.assertEqual(plaintext, expected_value)

    def test_text_as_bytes(self):
        test_value: bytes = self._test_bytes_string
        ciphertext: bytes = self._aes.encrypt(test_value)
        self.assertTrue(isinstance(ciphertext, bytes))
        plaintext: bytes = self._aes.decrypt(ciphertext)
        self.assertTrue(isinstance(plaintext, bytes))
        self.assertEqual(plaintext, test_value)

    def test_text_as_string_to_b64(self):
        test_value: str = self._test_string
        expected_value: str = self._test_string
        ciphertext: StringOrBytes = self._aes.encrypt_b64(
            test_value,
            to_string=True
        )
        self.assertTrue(isinstance(ciphertext, str))
        plaintext: str = self._aes.decrypt_b64(
            ciphertext,
            to_string=True
        )
        self.assertTrue(isinstance(plaintext, str))
        self.assertEqual(plaintext, expected_value)

    def test_text_as_string_to_b64_to_string(self):
        # test options
        test_value: str = self._test_string
        # test case
        ciphertext: StringOrBytes = self._aes.encrypt_b64(test_value, to_string=True)
        self.assertTrue(isinstance(ciphertext, str))
        plaintext: str = self._aes.decrypt_b64(ciphertext, to_string=True)
        self.assertTrue(isinstance(plaintext, str))
        self.assertEqual(plaintext, test_value)

    def test_text_as_bytes_to_b64_to_bytes(self):
        test_value: bytes = self._test_bytes_string
        expected_value: bytes = self._test_bytes_string
        ciphertext: StringOrBytes = self._aes.encrypt_b64(test_value, to_string=False)
        self.assertTrue(isinstance(ciphertext, bytes))
        plaintext: bytes = self._aes.decrypt_b64(ciphertext, to_string=False)
        self.assertTrue(isinstance(plaintext, bytes))
        self.assertEqual(plaintext, expected_value)

    def test_text_as_bytes_to_b64(self):
        test_value: bytes = self._test_bytes_string
        expected_value: bytes = self._test_bytes_string
        ciphertext: StringOrBytes = self._aes.encrypt_b64(test_value, to_string=False)
        self.assertTrue(isinstance(ciphertext, bytes))
        plaintext: bytes = self._aes.decrypt_b64(ciphertext, to_string=False)
        self.assertTrue(isinstance(plaintext, bytes))
        self.assertEqual(plaintext, expected_value)


class TestCryptoRSAHelper(unittest.TestCase):

    def setUp(self):
        self._test_string = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor ' \
                            'incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud ' \
                            'exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure ' \
                            'dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. ' \
                            'Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt ' \
                            'mollit anim id est laborum. '

        self._test_bytes_string = self._test_string.encode()

        self.rsa_public_key, self.rsa_private_key = RSACipher.generate_keys()

    def test_text_as_bytes_with_session_key(self):
        test_value: bytes = self._test_bytes_string
        expected_value: bytes = self._test_bytes_string

        aes_key: bytes = b'mysecretkey'

        rsa = RSACipher(self.rsa_public_key)
        session_key: bytes
        ciphertext: bytes

        session_key, ciphertext = rsa.encrypt(
            test_value,
            session_key=aes_key
        )

        self.assertTrue(isinstance(session_key, bytes))
        self.assertTrue(isinstance(ciphertext, bytes))

        rsa = RSACipher(self.rsa_private_key)

        plaintext: bytes = rsa.decrypt(
            ciphertext,
            session_key
        )

        self.assertTrue(isinstance(ciphertext, bytes))
        self.assertEqual(plaintext, expected_value)

    def test_text_as_string_with_session_key(self):
        test_value: str = self._test_string
        expected_value: bytes = self._test_bytes_string
        aes_key: str = 'mysecretkey'

        rsa = RSACipher(self.rsa_public_key)

        session_key, ciphertext = rsa.encrypt(
            test_value, session_key=aes_key
        )

        self.assertTrue(isinstance(session_key, bytes))
        self.assertTrue(isinstance(ciphertext, bytes))

        rsa = RSACipher(self.rsa_private_key)
        plaintext: bytes = rsa.decrypt(ciphertext, session_key)

        self.assertTrue(isinstance(ciphertext, bytes))
        self.assertEqual(plaintext, expected_value)

    def test_text_as_string_random_session_key(self):
        test_value: str = self._test_string
        expected_value: bytes = self._test_bytes_string

        rsa = RSACipher(self.rsa_public_key)

        session_key, ciphertext = rsa.encrypt(test_value)

        self.assertTrue(isinstance(session_key, bytes))
        self.assertTrue(isinstance(ciphertext, bytes))

        rsa = RSACipher(self.rsa_private_key)
        plaintext: bytes = rsa.decrypt(ciphertext, session_key)

        self.assertTrue(isinstance(ciphertext, bytes))
        self.assertEqual(plaintext, expected_value)

    def test_text_as_string_random_session_key_asb64(self):
        test_value: str = self._test_string
        expected_value: str = self._test_string

        public_rsa = RSACipher(
            self.rsa_public_key
        )
        dictionary = public_rsa.encrypt_b64(
            test_value,
            to_string=True
        )
        session_key: str = dictionary['session_key']
        ciphertext: str = dictionary['cipher_text']
        hashed: str = dictionary['hashed']

        self.assertTrue(isinstance(session_key, str))
        self.assertTrue(isinstance(ciphertext, str))
        self.assertTrue(isinstance(hashed, str))

        private_rsa = RSACipher(self.rsa_private_key)

        plaintext: StringOrBytes = private_rsa.decrypt_b64(
            ciphertext,
            session_key,
            to_string=True
        )

        self.assertTrue(isinstance(plaintext, str))
        self.assertEqual(plaintext, expected_value)

    def test_text_as_bytes_random_session_key_asb64(self):
        test_value: bytes = self._test_bytes_string
        expected_value: bytes = self._test_bytes_string

        public_rsa = RSACipher(self.rsa_public_key)

        dictionary = public_rsa.encrypt_b64(test_value, to_string=False)

        self.assertTrue(isinstance(dictionary['session_key'], bytes))
        self.assertTrue(isinstance(dictionary['cipher_text'], bytes))
        self.assertTrue(isinstance(dictionary['hashed'], bytes))

        private_rsa = RSACipher(self.rsa_private_key)

        plaintext: StringOrBytes = private_rsa.decrypt_b64(
            dictionary['cipher_text'],
            dictionary['session_key'],
            to_string=False
        )

        self.assertTrue(isinstance(plaintext, bytes))
        self.assertEqual(plaintext, expected_value)

    def test_text_as_bytes_to_b64(self):
        test_value: bytes = self._test_bytes_string
        expected_value: bytes = self._test_bytes_string
        aes_key: str = 'mysecretkey'
        rsa = RSACipher(self.rsa_public_key)

        dictionary = rsa.encrypt_b64(test_value, session_key=aes_key, to_string=False)

        self.assertTrue(isinstance(dictionary['session_key'], bytes))
        self.assertTrue(isinstance(dictionary['cipher_text'], bytes))
        self.assertTrue(isinstance(dictionary['hashed'], bytes))

        rsa = RSACipher(self.rsa_private_key)

        plaintext: StringOrBytes = rsa.decrypt_b64(
            dictionary['cipher_text'],
            dictionary['session_key'],
            to_string=False
        )

        self.assertTrue(isinstance(plaintext, bytes))
        self.assertEqual(plaintext, expected_value)
