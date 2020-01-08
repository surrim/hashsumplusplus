#include <cstdio>
#include <string>
#include <map>
#include <gcrypt.h>

static void throwIfError(const gcry_error_t& error) {
	if (error != GPG_ERR_NO_ERROR) {
		throw gcry_strsource(error) + std::string(" - ") + gcry_strerror(error);
	}
}

static int showHelp() {
	printf("%s", "hashsum [-t | --type ALGORITHM] FILE\n");
	return EXIT_FAILURE;
}

static const std::map<std::string, unsigned> ALGORITHMS = {
	{"", GCRY_MD_NONE},
	{"sha1", GCRY_MD_SHA1},
	{"rmd160", GCRY_MD_RMD160},
	{"md5", GCRY_MD_MD5},
	{"md4", GCRY_MD_MD4},
	{"md2", GCRY_MD_MD2},
	{"tiger", GCRY_MD_TIGER},
	{"tiger1", GCRY_MD_TIGER1},
	{"tiger2", GCRY_MD_TIGER2},
	{"haval", GCRY_MD_HAVAL},
	{"sha224", GCRY_MD_SHA224},
	{"sha256", GCRY_MD_SHA256},
	{"sha384", GCRY_MD_SHA384},
	{"sha512", GCRY_MD_SHA512},
	{"sha3-224", GCRY_MD_SHA3_224},
	{"sha3-256", GCRY_MD_SHA3_256},
	{"sha3-384", GCRY_MD_SHA3_384},
	{"sha3-512", GCRY_MD_SHA3_512},
	{"shake-128", GCRY_MD_SHAKE128},
	{"shake-256", GCRY_MD_SHAKE256},
	{"crc32", GCRY_MD_CRC32},
	{"crc32-rfc1510", GCRY_MD_CRC32_RFC1510},
	{"crc24-rfc2440", GCRY_MD_CRC24_RFC2440},
	{"whirlpool", GCRY_MD_WHIRLPOOL},
	{"gost", GCRY_MD_GOSTR3411_94},
	{"stribog256", GCRY_MD_STRIBOG256},
	{"stribog512", GCRY_MD_STRIBOG512},
	{"blake2b-512", GCRY_MD_BLAKE2B_512},
	{"blake2b-384", GCRY_MD_BLAKE2B_384},
	{"blake2b-256", GCRY_MD_BLAKE2B_256},
	{"blake2b-160", GCRY_MD_BLAKE2B_160},
	{"blake2s-256", GCRY_MD_BLAKE2S_256},
	{"blake2s-224", GCRY_MD_BLAKE2S_224},
	{"blake2s-160", GCRY_MD_BLAKE2S_160},
	{"blake2s-128", GCRY_MD_BLAKE2S_128}
};
static constexpr auto DEFAULT_ALGORITHM = "blake2b-256";

int main(int argc, char *argv[]) {
	auto algorithmText = DEFAULT_ALGORITHM;
	auto inputFileName = "-";
	for (auto i = 1; i < argc ; i++) {
		if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--type")) {
			if (i + 1 == argc) {
				return showHelp();
			}
			algorithmText = argv[i + 1];
			i++;
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			return showHelp();
		} else {
			inputFileName = argv[i];
		}
	}

	auto algorithm = ALGORITHMS.at(algorithmText);
	auto hashSize = gcry_md_get_algo_dlen(algorithm);

	gcry_md_handle *state = nullptr;
	throwIfError(gcry_md_open(&state, algorithm, 0));

	char buffer[BUFSIZ];
	FILE *file = nullptr;
	if (!strcmp(inputFileName, "-")) {
		file = stdin;
	} else {
		file = fopen(inputFileName, "r");
	}

	while (auto readBytes = fread(buffer, 1, BUFSIZ, file)) {
		gcry_md_write(state, buffer, readBytes);
	}
	auto hash = gcry_md_read(state, algorithm);
	for (auto i = 0u; i < hashSize; i++) {
		printf("%02x", hash[i]);
	}
	printf("  %s\n", inputFileName);
	gcry_md_close(state);
	fclose(file);

    return 0;
}
