
#include <android/log.h>

#define LOG_ON true
#define LOGD(...) if (LOG_ON) __android_log_print(ANDROID_LOG_DEBUG, "mazoku", __VA_ARGS__)
#define LOGE(...) if (LOG_ON) __android_log_print(ANDROID_LOG_ERROR, "mazoku", __VA_ARGS__)
#define LOGI(...) if (LOG_ON) __android_log_print(ANDROID_LOG_INFO, "mazoku", __VA_ARGS__)

#include "utils.cpp"
#include <string>
#include <sys/stat.h>
#include <algorithm>
#include "And64InlineHook.hpp"
#include <map>
#include <tuple>

using namespace std;

typedef struct {
	void*	reserved0;
	void*	reserved1;
	void*	reserved2;
	void*	begin;
	void*	finish;
} Aeo;

typedef struct {
	uint32_t		id;
	int 			unk_a;
	void*			code;
	unsigned int 	verdict;
	int				code_size;
	int 			block_size;
	bool			unk_b;
	int 			unk_c;
	int 			unk_d;
	int 			unk_e;
	int 			unk_f;
} Eo;

bool hasGameSafe = false, hasSpoofedLibs = false;
Aeo* (*anoGetExternalObjects)();
unsigned int (*anoCreateSWBackedIntegrity)(int, unsigned char *, size_t);
unsigned int (*anoCreateMemoryHashed)(const void*, unsigned int) = nullptr;

unsigned int (*anoParcelCreateMemABacked)(const void* src, unsigned int len);
unsigned int mazokuParcelCreateMemABacked(const void* src, unsigned int len) {
	char* lib = wherethis(src);
	if (lib) {
		//LOGI("[MemoryBackedScan]: %s(%p) [size=%ud]", lib, src, len);
	} else {
		//LOGI("[MemoryBackedScan]: ???(%p) [size=%ud]", src, len);
	}
	return anoParcelCreateMemABacked(src, len);
}

unsigned int (*anoParcelCreateMemBBacked)(const void* src, unsigned int len);
unsigned int mazokuParcelCreateMemBBacked(const void* src, unsigned int len) {
	char* lib = wherethis(src);
	if (lib) {
		//LOGI("[MemoryBackedScan]: %s(%p) [size=%ud]", lib, src, len);
	} else {
		//LOGI("[MemoryBackedScan]: ???(%p) [size=%ud]", src, len);
	}
	return anoParcelCreateMemABacked(src, len);
}

unsigned int (*unityProxy)(int attestationKey, void* src, size_t len);
unsigned int mazokuProxy(int attestationKey, void* src, size_t len) {
	char* lib = wherethis(src);
	if (lib) {
		LOGI("[UnityProxy]: %s(%p) [size=%zud]", lib, src, len);
	} else {
		LOGI("[UnityProxy]: ???(%p) [size=%zud]", src, len);
	}
	return unityProxy(attestationKey, src, len);
}

unsigned int (*anoParcelProxy)(void*);
unsigned int mazokuParcelProxy(void* unityNS) {
	uintptr_t proxyloc = (unityNS &&
						*reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(unityNS) + 0x10) &&
						*reinterpret_cast<uintptr_t*>(*reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(unityNS) + 0x10) + 0x58) &&
						*reinterpret_cast<uintptr_t*>(*reinterpret_cast<uintptr_t*>(*reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(unityNS) + 0x10) + 0x58)))
						? *reinterpret_cast<uintptr_t*>(*reinterpret_cast<uintptr_t*>(*reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(unityNS) + 0x10) + 0x58)) + 0x8
						: 0;
	if (proxyloc) {
		uintptr_t proxy = *(uintptr_t*) proxyloc;
		if (!unityProxy)
			unityProxy = (unsigned int (*)(int, void *, size_t))(proxy);
		if (reinterpret_cast<unsigned int (*)(int, void *, size_t)>(proxy) == unityProxy) {
			LOGI("Updated proxy[%p -> %p] to mazokuProxy[%p].", (void*) proxyloc, (void*) proxy, mazokuProxy);
			*(uintptr_t*) proxyloc = reinterpret_cast<uintptr_t>(mazokuProxy);
		}
	} else {
		LOGE("Unable to locate proxy function from libunity.so!");
	}
	return anoParcelProxy(unityNS);
}

std::map<std::string, std::tuple<uintptr_t, uintptr_t, size_t>> spoofedLibs;

void init_callback(uintptr_t start, uintptr_t end, const char* perms,
					 off_t offset, const char* dev,
					 unsigned int inode, const char* file)
{
	const char* last_slash = strrchr(file, '/');
	if (last_slash && strstr(last_slash, "/lib") && strstr(last_slash, ".so")) {
		char* lib = static_cast<char *>(malloc(strlen(last_slash + 1) + 1));
		if (lib) strcpy(lib, last_slash + 1);
		auto it = spoofedLibs.find(lib);
		if (it != spoofedLibs.end()) {
			LOGI("Found `%s` in spoof_target_libs!", lib);
			size_t len = end - start;
			void* vmcpy = malloc(len);
			if (!vmcpy) {
				LOGE("Unable to allocate memory! (size = [%zu])", len);
				return;
			} else
				memcpy(vmcpy, (void*) start, len);
			std::tuple<uintptr_t, uintptr_t, size_t>& stl = it->second;
			std::get<0>(stl) = start;
			std::get<1>(stl) = (uintptr_t) vmcpy;
			std::get<2>(stl) = len;
			LOGI("Created software backed copy of `%s`!", lib);
		}
	} else
		return;
	if (strstr(file, "/libanogs.so") && is_elf(start)) {
		hasGameSafe = true;
		anoGetExternalObjects = (Aeo* (*)()) (start + 0x29AF48);
		anoCreateSWBackedIntegrity = (unsigned int(*)(int, unsigned char *, size_t)) (start + 0x28D57C);
	}
}

std::vector<unsigned int> spid = {
		0x65ed4aa9,
		0x29e97f13,
		0x8852e992
};

std::vector<unsigned int> sped = {};

enum SPTAG {
	SPT_MEMHASH_A,
	SPT_MEMHASH_B,
	SPT_PARCEL
};

bool seekpatch(unsigned int id, void* code, int size)
{
	struct timespec loopnap{};
	loopnap.tv_sec = 1;
	loopnap.tv_nsec = 0;
	long index;
	auto it = std::find(spid.begin(), spid.end(), id);
	if (it != spid.end() && std::find(sped.begin(), sped.end(), id) == sped.end()) {
		index = std::distance(spid.begin(), it);
	} else
		return false;
	switch (index) {
		case SPT_MEMHASH_A:
			A64HookFunction((void*) ((uintptr_t) code + 820), (void*) mazokuParcelCreateMemABacked, (void**) &anoParcelCreateMemABacked);
			break;
		case SPT_MEMHASH_B:
			A64HookFunction((void*) ((uintptr_t) code + 696), (void*) mazokuParcelCreateMemBBacked, (void**) &anoParcelCreateMemBBacked);
			break;
		case SPT_PARCEL:
			A64HookFunction((void*) (uintptr_t) code, (void*) mazokuParcelProxy, (void**) &anoParcelProxy);
			break;
		default:
			return false;
	}
	sped.push_back(id);
	return true;
}

void mazoku_runtime(const std::string& spoofTargetLibs)
{
	struct timespec loopnap{};
	loopnap.tv_sec = 1;
	loopnap.tv_nsec = 0;
	ssize_t start = 0, end;
	std::string spoofedLib;
	LOGI("spoofTargetLibs [%s]", spoofTargetLibs.c_str());
	while ((end = spoofTargetLibs.find('\n')) != std::string::npos) {
		spoofedLib = spoofTargetLibs.substr(start, end - start);
		spoofedLibs[spoofedLib] = std::make_tuple(0, 0, 0);
		start = end + 1;
	}
	spoofedLib = spoofTargetLibs.substr(start, end - start);
	spoofedLibs[spoofedLib] = std::make_tuple(0, 0, 0);
	while (!hasGameSafe && !hasSpoofedLibs) {
		maps_pairs(init_callback);
		nanosleep(&loopnap, nullptr);
	}
	LOGI("anoGetExternalObjects [%p]", anoGetExternalObjects);
	LOGI("anoCreateSWBackedIntegrity [%p]", anoCreateSWBackedIntegrity);
	Aeo* anoExtObjs = anoGetExternalObjects();
	if (anoExtObjs) {
		LOGI("Aeo [%p]", anoExtObjs);
		size_t len, updlen;
		loopnap.tv_sec = 2;
		loopnap.tv_nsec = 0;
		do {
			len = ((uintptr_t) anoExtObjs->finish - (uintptr_t) anoExtObjs->begin) / sizeof(void*);
			nanosleep(&loopnap, nullptr);
		} while (!len);
		loopback:
		LOGI("Objects [%zu]", len);
		Eo** objector = (Eo**) anoExtObjs->begin;
		Eo* obj;
		for (int i = 0; i < len; i++) {
			obj = objector[i];
			if (seekpatch(obj->id, obj->code, obj->code_size)) {
				LOGI("extobj(%x) = {", obj->id);
				LOGI("\tunknown[a](int)  = %d", obj->unk_a);
				LOGI("\tcode(void*)      = %p", obj->code);
				LOGI("\tverdict(hex)     = %X", obj->verdict);
				LOGI("\tcode_size(int)   = %d", obj->code_size);
				LOGI("\tblock_size(int)  = %d", obj->block_size);
				LOGI("\tunknown[b](bool) = %d", obj->unk_b);
				LOGI("\tunknown[c](int)  = %d", obj->unk_c);
				LOGI("\tunknown[d](int)  = %d", obj->unk_d);
				LOGI("\tunknown[e](int)  = %d", obj->unk_e);
				LOGI("\tunknown[f](int)  = %d", obj->unk_f);
				LOGI("}");
				unsigned int updVerdict = anoCreateSWBackedIntegrity(0, (unsigned char *) obj->code, obj->code_size);
				LOGI("SoftwareBackedAttestation(%p, %d) = [%X]", obj->code, obj->code_size, updVerdict);
				if (updVerdict != obj->verdict) {
					LOGI("[SWBA] Found modifications to object(%x)!", obj->id);
					obj->verdict = updVerdict;
					LOGI("Hacked leaf verdict of object -> %X", updVerdict);
				}
			} else
				LOGI("extobj(%x) {...}", obj->id);
		}
		if (spid.size() > sped.size()) {
			do {
				updlen = ((uintptr_t) anoExtObjs->finish - (uintptr_t) anoExtObjs->begin) / sizeof(void*);
				nanosleep(&loopnap, nullptr);
			} while (updlen <= len);
			len = updlen;
			goto loopback;
		} else
			LOGI("Completed injection!");
	} else {
		LOGE("nulled Aeo found, exiting..");
	}
}