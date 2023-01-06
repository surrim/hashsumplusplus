#include <gcrypt.h>
#include <array>
#include <iostream>
#include <list>
#include <map>
#include <string>
#include <vector>

static void throwIfError(const gcry_error_t& error) {
	if (error != GPG_ERR_NO_ERROR) {
		throw gcry_strsource(error) + std::string(" - ") + gcry_strerror(error);
	}
}

static std::string toHexString(const std::vector<std::byte>& data) {
	static constexpr std::array<char, 16> HEX = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	auto hexString = std::string(2 * data.size(), '\0');
	for (auto i = 0; i < data.size(); i++) {
		auto byte = uint8_t(data[i]);
		hexString[2 * i] = HEX[byte >> 4];
		hexString[2 * i + 1] = HEX[byte & 0xF];
	}
	return hexString;
}

struct Algorithm {
	gcry_md_algos id;
	std::string description;
};

static const std::map<std::string, Algorithm> ALGORITHMS = { // see src/gcrypt.h.in from libgcrypt
	{"none", {GCRY_MD_NONE, "None"}},
	{"md5", {GCRY_MD_MD5, "MD5"}},
	{"sha1", {GCRY_MD_SHA1, "SHA-1"}},
	{"rmd160", {GCRY_MD_RMD160, "RIPEMD-160"}},
	{"md2", {GCRY_MD_MD2, "MD2"}},
	{"tiger", {GCRY_MD_TIGER, "TIGER/192 as used by gpg <= 1.3.2"}},
	{"haval", {GCRY_MD_HAVAL, "HAVAL, 5 pass, 160 bit"}},
	{"sha256", {GCRY_MD_SHA256, "SHA-256"}},
	{"sha384", {GCRY_MD_SHA384, "SHA-384"}},
	{"sha512", {GCRY_MD_SHA512, "SHA-512"}},
	{"sha224", {GCRY_MD_SHA224, "SHA-224"}},
	{"md4", {GCRY_MD_MD4, "MD4"}},
	{"crc32", {GCRY_MD_CRC32, "CRC-32 (as in ISO 3309)"}},
	{"crc32-rfc1510", {GCRY_MD_CRC32_RFC1510, "CRC-32 (as in RFC 1510)"}},
	{"crc24-rfc2440", {GCRY_MD_CRC24_RFC2440, "CRC-24 (as in RFC 2440)"}},
	{"whirlpool", {GCRY_MD_WHIRLPOOL, "Whirlpool"}},
	{"tiger1", {GCRY_MD_TIGER1, "TIGER1"}},
	{"tiger2", {GCRY_MD_TIGER2, "TIGER2"}},
	{"gostr3411-94", {GCRY_MD_GOSTR3411_94, "GOST R 34.11-94 / GOST 34.311-95"}},
	{"stribog256", {GCRY_MD_STRIBOG256, "GOST R 34.11-2012 (Stribog) / RFC 6986, 256"}},
	{"stribog512", {GCRY_MD_STRIBOG512, "GOST R 34.11-2012 (Stribog) / RFC 6986, 512"}},
	{"gostr3411-cp", {GCRY_MD_GOSTR3411_CP, "GOST R 34.11-94 with CryptoPro-A S-Box"}},
	{"sha3-224", {GCRY_MD_SHA3_224, "SHA3-224"}},
	{"sha3-256", {GCRY_MD_SHA3_256, "SHA3-256"}},
	{"sha3-384", {GCRY_MD_SHA3_384, "SHA3-384"}},
	{"sha3-512", {GCRY_MD_SHA3_512, "SHA3-512"}},
	{"shake128", {GCRY_MD_SHAKE128, "SHAKE128"}},
	{"shake256", {GCRY_MD_SHAKE256, "SHAKE256"}},
	{"blake2b-512", {GCRY_MD_BLAKE2B_512, "BLAKE2b-512"}},
	{"blake2b-384", {GCRY_MD_BLAKE2B_384, "BLAKE2b-384"}},
	{"blake2b-256", {GCRY_MD_BLAKE2B_256, "BLAKE2b-256, default"}},
	{"blake2b-160", {GCRY_MD_BLAKE2B_160, "BLAKE2b-160"}},
	{"blake2s-256", {GCRY_MD_BLAKE2S_256, "BLAKE2s-256"}},
	{"blake2s-224", {GCRY_MD_BLAKE2S_224, "BLAKE2s-114"}},
	{"blake2s-160", {GCRY_MD_BLAKE2S_160, "BLAKE2s-160"}},
	{"blake2s-128", {GCRY_MD_BLAKE2S_128, "BLAKE2s-128"}},
	{"sm3", {GCRY_MD_SM3, "SM3"}},
	{"sha512-256", {GCRY_MD_SHA512_256, "SHA-512/256"}},
	{"sha512-224", {GCRY_MD_SHA512_224, "SHA-512/224"}},
};

static void showHelp() {
	std::cout << "Usage hashsum [OPTION]... FILE..." << std::endl
		<< "  -h, --help" << std::endl
		<< "  -a, --algorithm ALGORITHM   Set the hash algorithm" << std::endl;
	for (const auto& algorithm: ALGORITHMS) {
		auto spaces = std::string(15 - algorithm.first.size(), ' ');
		std::cout << "      " << algorithm.first << spaces << algorithm.second.description << std::endl;
	}
}

static constexpr auto DEFAULT_ALGORITHM = std::string("blake2b-256");

int main(int argc, char *argv[]) {
	auto algorithmText = DEFAULT_ALGORITHM;
	auto inputFileNames = std::list<std::string>();
	for (auto i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--algorithm")) {
			if (i + 1 == argc) {
				showHelp();
				return 1;
			}
			algorithmText = argv[i + 1];
			i++;
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			showHelp();
			return 0;
		} else {
			inputFileNames.push_back(argv[i]);
		}
	}
	if (inputFileNames.empty()) {
		inputFileNames.push_back("-");
	}

	auto algorithm = ALGORITHMS.at(algorithmText).id;
	auto hashSize = gcry_md_get_algo_dlen(algorithm);

	gcry_md_handle *state = nullptr;
	throwIfError(gcry_md_open(&state, algorithm, 0));

	auto buffer = std::vector<std::byte>(32768);
	for (auto inputFileName: inputFileNames) {
		FILE *file = nullptr;
		if (inputFileName == "-") {
			file = stdin;
		} else {
			file = fopen(inputFileName.c_str(), "r");
		}
		if (file != nullptr) {
			gcry_md_reset(state);

			while (auto readBytes = fread(buffer.data(), 1, buffer.size(), file)) {
				gcry_md_write(state, buffer.data(), readBytes);
			}
			fclose(file);

			auto hashPointer = (const std::byte*)gcry_md_read(state, algorithm);
			auto hash = std::vector<std::byte>(hashPointer, hashPointer + hashSize);
			std::cout << toHexString(hash) << "  " << inputFileName << std::endl;
		} else {
			std::cerr << "hashsum: " << inputFileName << ": No such file or directory" << std::endl;
		}
	}
	gcry_md_close(state);

    return 0;
}
