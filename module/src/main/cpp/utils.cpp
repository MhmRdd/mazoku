
#pragma once

extern "C" {
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <inttypes.h>

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
					char* lib_name = static_cast<char *>(malloc(strlen(last_slash + 1) + 1));
					if (lib_name) strcpy(lib_name, last_slash + 1);
					free(line);
					fclose(maps);
					return lib_name;
				}
			}
		}
	}
	free(line);
	fclose(maps);
	return NULL;
}

}