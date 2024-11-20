
#pragma once

extern "C" {
#include <stdio.h>

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
}