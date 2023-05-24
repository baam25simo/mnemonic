import hashlib
import unicodedata
import secrets
import os

class Mnemonic(object):

    CURR_DIR = os.path.dirname(__file__)

    def __init__(self, language: str = "english"):
        self.language = language
        self.itercount_seed = 2048
        with open(os.path.join(self.CURR_DIR, f"wordlist/{self.language}.txt"), "r") as ff:
            self.words = [w.strip() for w in ff.readlines()]

    def _entropy_gen(self, _ent: int = 128):
        # Generate a random number of 256 byte
        # Divide by 8 since 1 byte = 8 bits
        self._rand = secrets.token_bytes(_ent // 8)
        if _ent not in [128, 160, 192, 224, 256]:
            raise Exception(f"Byte number must be in [128, 160, 192, 224, 256]. Reeived {_ent} instead.")
        return self._rand
    
    def _checksum_gen(self, _secret: bytes):
        h = hashlib.sha256(_secret).hexdigest()
        # return 256 bits array
        # get (bytes) * 8 [bits] // 32 [bits]
        cs =  bin(int(h, 16))[2:].zfill(256)[:len(_secret) * 8 // 32]
        return cs
    
    def _to_entropy(self, _mnemonic: list):
        _entropy_bits, _cs_bits = self._bits_from_mnemonic(_mnemonic)
        ll = len(_entropy_bits)
        _entropy = int(_entropy_bits, 2).to_bytes(ll // 8, 'big')
        _cs_check = self._checksum_gen(_entropy)
        if _cs_bits != _cs_check:
            raise Exception("Invalid checksum")
        return _entropy
    
    def _idx_gen(self, _secret: bytes):
        if len(_secret) not in [16, 20, 24, 28, 32]:
            raise Exception(f"Bytes length not in [16, 20, 24, 28, 32]. Length of {len(_secret)} given instead.")
        _cs = self._checksum_gen(_secret)
        _ent_cs = (bin(int.from_bytes(_secret, 'big'))[2:].zfill(len(_secret) * 8) +
                   _cs
                   )
        idx = []
        for i in range(len(_ent_cs) // 11):
            idx.append(int(_ent_cs[i * 11:(i+1) * 11], 2))
        return idx
    
    def _mnemonic_gen(self, _idx: list):
        self.mnemonic = list()
        for i in _idx:
            self.mnemonic.append(self.words[i])
        return self.mnemonic
    
    def mnemonic_gen(self, _entropy: bytes):
        idx = self._idx_gen(_entropy)
        return self._mnemonic_gen(idx)        
    
    @staticmethod
    def normalize_str(_string: str):
        _norm_str = unicodedata.normalize('NFKC', _string)
        return _norm_str.encode('utf-8', errors='ignore')
    
    def _seed_gen(self, _mnemonic: list, _passphrase: str = ""):
        _mnemonic_encoded = self.normalize_str(' '.join(_mnemonic))
        _pwd_encoded = self.normalize_str('mnemonic' + _passphrase)
        seed = hashlib.pbkdf2_hmac('sha512', _mnemonic_encoded, _pwd_encoded, self.itercount_seed)
        seed = seed[:64]
        return seed
        
    def _bits_from_mnemonic(self, _mnemonic: list):
        _b = map(lambda x: bin(self.words.index(x))[2:].zfill(11), _mnemonic)
        b = "".join(_b)
        l = len(b)
        _entropy = b[: l // 33 * 32]
        _cs = b[-l // 33 :]
        return _entropy, _cs
    
    def check(self, mnemonic: list):
        if len(mnemonic) not in [12, 15, 18, 21, 24]:
            return False
        _entropy_bits, _cs_bits = self._bits_from_mnemonic(mnemonic)
        ll = len(_entropy_bits)
        _entropy = int(_entropy_bits, 2).to_bytes(ll // 8, 'big')
        _cs_check = self._checksum_gen(_entropy)
        return _cs_bits == _cs_check

    def generate(self, mnemonic: list, passphrase: str = ""):
        return self._seed_gen(mnemonic, passphrase)
