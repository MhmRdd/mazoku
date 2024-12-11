
#pragma once

extern "C" {
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <inttypes.h>

static const uint32_t k[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t h[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

#define ROTR(x, n) ((x >> n) | (x << (32 - n)))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

static void sha256_transform(const uint8_t* message_chunk) {
	uint32_t w[64];
	for (int i = 0; i < 16; ++i) {
		w[i] = (message_chunk[i * 4] << 24) |
			   (message_chunk[i * 4 + 1] << 16) |
			   (message_chunk[i * 4 + 2] << 8) |
			   (message_chunk[i * 4 + 3]);
	}
	for (int i = 16; i < 64; ++i) {
		w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
	}
	uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
	uint32_t e = h[4], f = h[5], g = h[6], temp_h = h[7];
	for (int i = 0; i < 64; ++i) {
		uint32_t temp1 = temp_h + SIGMA1(e) + CH(e, f, g) + k[i] + w[i];
		uint32_t temp2 = SIGMA0(a) + MAJ(a, b, c);
		temp_h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += temp_h;
}


uint8_t* sha256(const void* data, size_t len) {
	const uint8_t* message = (const uint8_t*)data;
	size_t new_len = len + 1;
	while (new_len % 64 != 56) new_len++;
	auto* padded = (uint8_t*) calloc(new_len + 8, 1);
	memcpy(padded, message, len);
	padded[len] = 0x80;
	uint64_t bit_len = len * 8;
	for (int i = 0; i < 8; ++i) {
		padded[new_len + 7 - i] = bit_len >> (i * 8);
	}
	for (size_t i = 0; i < new_len; i += 64) {
		sha256_transform(padded + i);
	}
	uint8_t* hash = (uint8_t*) malloc(32);
	for (int i = 0; i < 8; ++i) {
		hash[i * 4] = (h[i] >> 24) & 0xff;
		hash[i * 4 + 1] = (h[i] >> 16) & 0xff;
		hash[i * 4 + 2] = (h[i] >> 8) & 0xff;
		hash[i * 4 + 3] = h[i] & 0xff;
	}
	free(padded);
	return hash;
}

uint8_t* fsha256(const char* hashpath) {
	FILE* file = fopen(hashpath, "rb");
	if (!file) return nullptr;
	auto* hash = (uint8_t*) malloc(32);
	if (!hash) {
		fclose(file);
		return nullptr;
	}
	size_t len = fread(hash, 1, 32, file);
	if (len != 32) {
		free(hash);
		fclose(file);
		return nullptr;
	}
	fclose(file);
	return hash;
}

bool csha256(const uint8_t* hasha, const uint8_t* hashb) {
	for (size_t i = 0; i < 32; ++i) {
		if (hasha[i] != hashb[i])
			return false;
	}
	return true;
}

void *castPlus(void* ptr, uintptr_t off) {
	return (void*) ((uintptr_t) ptr + off);
}

void *castPPlus(void* ptr, uintptr_t off) {
	return (void*) (*(uintptr_t*) ptr + off);
}


char* getDescription(const char *filePath) {
	FILE *inputFile = fopen(filePath, "r");
	if (!inputFile) {
		perror("Could not open file.");
		return NULL;
	}
	char buffer[512];
	char *description = NULL;
	while (fgets(buffer, sizeof(buffer), inputFile)) {
		if (strncmp(buffer, "description=", 12) == 0) {
			description = strdup(buffer + 12);
			size_t len = strlen(description);
			if (len > 0 && description[len - 1] == '\n') {
				description[len - 1] = '\0';
			}
			break;
		}
	}
	fclose(inputFile);
	return description;
}

void updateDescription(const char *filePath, const char *newDescription) {
	FILE *inputFile = fopen(filePath, "r");
	if (!inputFile) {
		perror("Could not open file.");
		return;
	}
	char *lines[256];
	char buffer[512];
	int count = 0;
	while (fgets(buffer, sizeof(buffer), inputFile)) {
		lines[count] = strdup(buffer);
		count++;
	}
	fclose(inputFile);
	for (int i = 0; i < count; i++) {
		if (strncmp(lines[i], "description=", 12) == 0) {
			free(lines[i]);
			lines[i] = (char*) malloc(strlen(newDescription) + 13);
			sprintf(lines[i], "description=%s\n", newDescription);
		}
	}
	FILE *outputFile = fopen(filePath, "w");
	if (!outputFile) {
		perror("Could not write to file.");
		return;
	}
	for (int i = 0; i < count; i++) {
		fputs(lines[i], outputFile);
		free(lines[i]);
	}
	fclose(outputFile);
}

char* readstr(int fd) {
	char *result = NULL;
	size_t length = 0;
	size_t capacity = 16;
	result = (char*) malloc(capacity);
	if (result == NULL) {
		LOGE("Memory allocation failed!");
		return NULL;
	}
	char buffer;
	ssize_t bytesRead;
	while ((bytesRead = read(fd, &buffer, 1)) > 0) {
		if (buffer == '\0') {
			break;
		}
		if (length + 1 >= capacity) {
			capacity *= 2;
			char *temp = (char*) realloc(result, capacity);
			if (temp == NULL) {
				LOGE("Memory reallocation failed!");
				free(result);
				return NULL;
			}
			result = temp;
		}
		result[length++] = buffer;
	}
	if (bytesRead < 0) {
		LOGE("Read error!");
		free(result);
		return NULL;
	}
	result[length] = '\0';
	return result;
}

void writestr(int fd, char* src) {
	write(fd, src, strlen(src));
	write(fd, "\0", sizeof(char));
}

long filesize(FILE* file) {
	fseek(file, 0, SEEK_END);
	long file_size = ftell(file);
	fseek(file, 0, SEEK_SET);
	return file_size;
}

bool is_elf(uintptr_t start) {
	unsigned char *data = (unsigned char *)start;
	if (data[EI_MAG0] == ELFMAG0 &&
		data[EI_MAG1] == ELFMAG1 &&
		data[EI_MAG2] == ELFMAG2 &&
		data[EI_MAG3] == ELFMAG3) {
		return true;
	}
	return false;
}

typedef void (*map_callback)(uintptr_t start, uintptr_t end, const char* perms,
		off_t offset, const char* dev,
		unsigned int inode, const char* file);

void maps_pairs(map_callback callback)
{
	FILE *file = fopen("/proc/self/maps", "r");
	if (!file) {
		perror("Failed to open `/proc/self/maps`.");
		return;
	}
	char line[1024];
	while (fgets(line, sizeof(line), file)) {
		uintptr_t start, end;
		char perms[5];
		off_t offset;
		char dev[6];
		unsigned int inode;
		char filepath[1024] = {0};
		if (sscanf(line, "%lx-%lx %4s %lx %5s %x %1023[^\n]", &start, &end, perms, &offset, dev, &inode, filepath) >= 7) {
			callback(start, end, perms, offset, dev, inode, filepath);
		}
	}
	fclose(file);
}

char* wherethis(const void* src) {
	FILE* maps = fopen("/proc/self/maps", "r");
	if (!maps) return NULL;
	uintptr_t address = (uintptr_t)src;
	char* line = NULL;
	size_t len = 0;
	while (getline(&line, &len, maps) != -1) {
		uintptr_t start, end;
		char perms[5], path[256] = "";
		if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %*x %*x:%*x %*u %255[^\n]",
				   &start, &end, perms, path) >= 3) {
			if (address >= start && address <= end) {
				const char* last_slash = strrchr(path, '/');
				if (last_slash && strstr(last_slash, "/lib") && strstr(last_slash, ".so")) {
					char *lib_name = static_cast<char *>(malloc(strlen(last_slash + 1) + 1));
					memset(lib_name, 0, strlen(last_slash + 1) + 1);
					if (lib_name) strcpy(lib_name, last_slash + 1);
					free(line);
					fclose(maps);
					return lib_name;
				}
				char* name = static_cast<char *>(malloc(strlen(path) + 1));
				memset(name, 0, strlen(path) + 1);
				if (name) strcpy(name, path);
				free(line);
				fclose(maps);
				return name;
				/*if (strstr(path, "[anon:objects_external_alloc]")) {
					char* obj_name = static_cast<char *>(malloc(strlen(path) + 1));
					memset(obj_name, 0, strlen(path) + 1);
					if (obj_name) strcpy(obj_name, path);
					free(line);
					fclose(maps);
					return obj_name;
				}*/
			}
		}
	}
	free(line);
	fclose(maps);
	return NULL;
}

}