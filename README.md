# rsa-aes-hybrid-encryption


 + AESCipher:
    
    - encrypt(self, text: StringOrBytes) -> bytes:
    - decrypt(self, cipher_text: StringOrBytes) -> bytes
    - encrypt_b64(self, text: StringOrBytes, to_string=False) -> StringOrBytes
    - decrypt_b64(self, cipher_text: StringOrBytes, to_string=False) -> StringOrBytes
    
    
 + RSACipher:
 
    - generate_keys(cls) -> typing.Tuple[str, str]
    - generate(cls) -> RSA.RsaKey
    - hashed(text: StringOrBytes) -> str
    - encrypt(self, text: StringOrBytes) -> bytes:
    - decrypt(self, cipher_text: StringOrBytes) -> bytes
    - encrypt_b64(self, text: StringOrBytes, to_string=False) -> StringOrBytes
    - decrypt_b64(self, cipher_text: StringOrBytes, to_string=False) -> StringOrBytes