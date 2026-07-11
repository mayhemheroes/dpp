/*
 * standalone_main.cpp — run-once libFuzzer-free driver for the dpp harnesses.
 * Reads a single input file and calls LLVMFuzzerTestOneInput once, so a crashing
 * input can be replayed under a debugger without the libFuzzer runtime.
 */
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
	if (argc != 2) {
		std::fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
		return 1;
	}
	FILE *f = std::fopen(argv[1], "rb");
	if (!f) {
		std::fprintf(stderr, "failed to open %s\n", argv[1]);
		return 2;
	}
	std::fseek(f, 0, SEEK_END);
	long sz = std::ftell(f);
	std::fseek(f, 0, SEEK_SET);
	if (sz < 0) { std::fclose(f); return 3; }
	std::vector<uint8_t> buf(static_cast<size_t>(sz));
	if (sz > 0 && std::fread(buf.data(), 1, static_cast<size_t>(sz), f) != static_cast<size_t>(sz)) {
		std::fclose(f);
		std::fprintf(stderr, "read failed\n");
		return 4;
	}
	std::fclose(f);
	LLVMFuzzerTestOneInput(buf.data(), buf.size());
	return 0;
}
