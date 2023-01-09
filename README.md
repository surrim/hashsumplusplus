# hashsum++

Small C++20 linux tool to calculate hash sums like `sha1sum`, `sha256sum`, `b2sum` etc.

It uses `libgcrypt` from GnuPG, which has many optimisations - it's even faster than many other tools around.

```
hashsum++ --help
Usage hashsum++ [OPTION]... FILE...
  -h, --help
  -a, --algorithm ALGORITHM   Set the hash algorithm
      blake2b-160    BLAKE2b-160
      blake2b-256    BLAKE2b-256, defauit
      blake2b-384    BLAKE2b-384
      blake2b-512    BLAKE2b-512
      blake2s-128    BLAKE2s-128
      blake2s-160    BLAKE2s-160
      blake2s-224    BLAKE2s-114
      blake2s-256    BLAKE2s-256
      crc24-rfc2440  CRC-24 (as in RFC 2440)
      crc32          CRC-32 (as in ISO 3309)
      crc32-rfc1510  CRC-32 (as in RFC 1510)
      gostr3411-94   GOST R 34.11-94 / GOST 34.311-95
      gostr3411-cp   GOST R 34.11-94 with CryptoPro-A S-Box
      haval          HAVAL, 5 pass, 160 bit
      md2            MD2
      md4            MD4
      md5            MD5
      none           None
      rmd160         RIPEMD-160
      sha1           SHA-1
      sha224         SHA-224
      sha256         SHA-256
      sha3-224       SHA3-224
      sha3-256       SHA3-256
      sha3-384       SHA3-384
      sha3-512       SHA3-512
      sha384         SHA-384
      sha512         SHA-512
      sha512-224     SHA-512/224
      sha512-256     SHA-512/256
      shake128       SHAKE128
      shake256       SHAKE256
      sm3            SM3
      stribog256     GOST R 34.11-2012 (Stribog) / RFC 6986, 256
      stribog512     GOST R 34.11-2012 (Stribog) / RFC 6986, 512
      tiger          TIGER/192 as used by gpg <= 1.3.2
      tiger1         TIGER1
      tiger2         TIGER2
      whirlpool      Whirlpool

```

