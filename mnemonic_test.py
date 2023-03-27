# -*- coding: utf-8 -*-
import json
import unittest
import random

from mnemonic import Mnemonic

class MnemonicTest(unittest.TestCase):
    def _check_list(self, language: str, vectors: list) -> None:
        mnemo = Mnemonic(language)
        for v in vectors:
            code = bytes.fromhex(v[0])
            idx = mnemo._idx_gen(code)
            words = mnemo._mnemonic_gen(idx)
            seed = mnemo._seed_gen(words, "TREZOR")
            self.assertIs(mnemo.check(v[1].split(' ')), True)
            self.assertEqual(v[1].split(' '), words)
            self.assertEqual(v[2], seed.hex())

    def test_vectors(self) -> None:
        with open("test_vectors.json", "r") as f:
            vectors = json.load(f)
        for lang in vectors.keys():
            self._check_list(lang, vectors[lang])

    def test_utf8_nfkd(self) -> None:
        # The same sentence in various UTF-8 forms
        words_nfkd = "Pr\u030ci\u0301s\u030cerne\u030c z\u030clut\u030couc\u030cky\u0301 ku\u030an\u030c u\u0301pe\u030cl d\u030ca\u0301belske\u0301 o\u0301dy za\u0301ker\u030cny\u0301 uc\u030cen\u030c be\u030cz\u030ci\u0301 pode\u0301l zo\u0301ny u\u0301lu\u030a"
        words_nfc = "P\u0159\xed\u0161ern\u011b \u017elu\u0165ou\u010dk\xfd k\u016f\u0148 \xfap\u011bl \u010f\xe1belsk\xe9 \xf3dy z\xe1ke\u0159n\xfd u\u010de\u0148 b\u011b\u017e\xed pod\xe9l z\xf3ny \xfal\u016f"
        words_nfkc = "P\u0159\xed\u0161ern\u011b \u017elu\u0165ou\u010dk\xfd k\u016f\u0148 \xfap\u011bl \u010f\xe1belsk\xe9 \xf3dy z\xe1ke\u0159n\xfd u\u010de\u0148 b\u011b\u017e\xed pod\xe9l z\xf3ny \xfal\u016f"
        words_nfd = "Pr\u030ci\u0301s\u030cerne\u030c z\u030clut\u030couc\u030cky\u0301 ku\u030an\u030c u\u0301pe\u030cl d\u030ca\u0301belske\u0301 o\u0301dy za\u0301ker\u030cny\u0301 uc\u030cen\u030c be\u030cz\u030ci\u0301 pode\u0301l zo\u0301ny u\u0301lu\u030a"

        passphrase_nfkd = (
            "Neuve\u030cr\u030citelne\u030c bezpec\u030cne\u0301 hesli\u0301c\u030cko"
        )
        passphrase_nfc = "Neuv\u011b\u0159iteln\u011b bezpe\u010dn\xe9 hesl\xed\u010dko"
        passphrase_nfkc = (
            "Neuv\u011b\u0159iteln\u011b bezpe\u010dn\xe9 hesl\xed\u010dko"
        )
        passphrase_nfd = (
            "Neuve\u030cr\u030citelne\u030c bezpec\u030cne\u0301 hesli\u0301c\u030cko"
        )

        seed_nfkd = Mnemonic().generate(words_nfkd.split(' '), passphrase_nfkd)
        seed_nfc = Mnemonic().generate(words_nfc.split(' '), passphrase_nfc)
        seed_nfkc = Mnemonic().generate(words_nfkc.split(' '), passphrase_nfkc)
        seed_nfd = Mnemonic().generate(words_nfd.split(' '), passphrase_nfd)

        self.assertEqual(seed_nfkd, seed_nfc)
        self.assertEqual(seed_nfkd, seed_nfkc)
        self.assertEqual(seed_nfkd, seed_nfd)
    
    def test_failed_checksum(self) -> None:
        code = (
            "bless cloud wheel regular tiny venue bird web grief security dignity zoo"
        )
        mnemo = Mnemonic("english")
        self.assertFalse(mnemo.check(code))
    
    def test_to_entropy(self) -> None:
        data = [bytes(random.getrandbits(8) for _ in range(32)) for _ in range(1024)]
        data.append(b"Lorem ipsum dolor sit amet amet.")
        m = Mnemonic("english")
        for d in data:
            self.assertEqual(m._to_entropy(m.mnemonic_gen(d)), d)

def __main__() -> None:
    unittest.main()


if __name__ == "__main__":
    __main__()