
#include <android/log.h>

#define LOG_ON true
#define LOGD(...) if (LOG_ON) __android_log_print(ANDROID_LOG_DEBUG, "mazoku", __VA_ARGS__)
#define LOGE(...) if (LOG_ON) __android_log_print(ANDROID_LOG_ERROR, "mazoku", __VA_ARGS__)
#define LOGW(...) if (LOG_ON) __android_log_print(ANDROID_LOG_WARN, "mazoku", __VA_ARGS__)
#define LOGI(...) if (LOG_ON) __android_log_print(ANDROID_LOG_INFO, "mazoku", __VA_ARGS__)

#include "utils.cpp"
#include <string>
#include <sys/stat.h>
#include <algorithm>
#include "And64InlineHook.hpp"
#include <map>
#include <tuple>
#include <set>
#include <sys/mman.h>
#include <fstream>
#include <sstream>
#include <iomanip>

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

std::map<std::string, std::set<std::tuple<uintptr_t, uintptr_t, size_t>>> spoofedLibs;

bool spoofTargetLib(const std::string& lib) {
	auto it = spoofedLibs.find(lib);
	bool isAddedAtLeastOnce = false;
	if (it != spoofedLibs.end()) {
		auto &list = it->second;
		std::ifstream maps("/proc/self/maps");
		if (!maps.is_open()) {
			LOGE("Unable to open `/proc/self/maps`!");
			return false;
		}
		std::string line;
		while (std::getline(maps, line)) {
			size_t pos1 = line.find('-');
			size_t pos2 = line.find(' ', pos1);
			size_t pos3 = line.find(' ', pos2 + 1);
			size_t pos4 = line.find(' ', pos3 + 1);
			size_t pos5 = line.find(' ', pos4 + 1);
			size_t pos6 = line.find(' ', pos5 + 1);
			std::string start_str = line.substr(0, pos1);
			std::string end_str = line.substr(pos1 + 1, pos2 - pos1 - 1);
			std::string perms = line.substr(pos2 + 1, pos3 - pos2 - 1);
			std::string offset_str = line.substr(pos3 + 1, pos4 - pos3 - 1);
			std::string dev = line.substr(pos4 + 1, pos5 - pos4 - 1);
			std::string inode_str = line.substr(pos5 + 1, pos6 - pos5 - 1);
			std::string file = (pos6 != std::string::npos) ? line.substr(pos6 + 1) : "";
			uintptr_t start = std::stoul(start_str, nullptr, 16);
			uintptr_t end = std::stoul(end_str, nullptr, 16);
			off_t offset = std::stoll(offset_str, nullptr, 16);
			unsigned int inode = std::stoul(inode_str);
			//LOGI("%s", line.c_str());
			if (perms == "r-xp" && file.ends_with("/" + lib)) {
				size_t len = end - start;
				for (const auto& deny : it->second) {
					if (std::get<0>(deny) == start && std::get<0>(deny) + std::get<2>(deny) == end)
						return false;
				}
				void *vmcpy = malloc(len);
				if (!vmcpy) {
					LOGE("Unable to allocate memory! (size = [%zu])", len);
					continue;
				} else
					memcpy(vmcpy, (void *) start, len);
				mprotect(vmcpy, len, PROT_READ);
				it->second.emplace(start, (uintptr_t) vmcpy, len);
				isAddedAtLeastOnce = true;
				LOGI("Created software backed copy of `%s`[%p-%p]!", lib.c_str(),
					 (void *) start, (void *) end);
			}
		}
	}
	return isAddedAtLeastOnce;
}

void *spoofScanTarget(void *at, size_t len) {
	char* lib = wherethis(at);
	if (lib) {
		for (const auto& [slib, denylist] : spoofedLibs) {
			if (lib == slib) {
				for (const auto& deny : denylist) {
					if (std::get<0>(deny) <= (uintptr_t) at && std::get<0>(deny) + std::get<2>(deny) >= (uintptr_t) at + len) {
						LOGI("Scan[(%s + %p) (size = [%zu]) -> [%p (size = [%zu])]", lib, (void*) ((uintptr_t) at - std::get<0>(deny)), len, (void*) std::get<1>(deny), std::get<2>(deny));
						return (void*) (std::get<1>(deny) + ((uintptr_t) at - std::get<0>(deny)));
					}
				}
			}
		}
		//LOGI("`%s` was found in spoofed target libs.", lib);
	}
	return at;
}

Aeo* (*anoGetExternalObjects)();
unsigned int (*anoCreateSWBackedIntegrity)(int, unsigned char *, size_t) = nullptr;
unsigned int (*anoCreateMemoryHashed)(const void*, unsigned int) = nullptr;

unsigned int (*anoParcelCreateMemABacked)(const void* src, unsigned int len);
unsigned int mazokuParcelCreateMemABacked(const void* src, unsigned int len) {
	return anoParcelCreateMemABacked(spoofScanTarget((void*) src, len), len);
}

unsigned int (*anoParcelCreateMemBBacked)(const void* src, unsigned int len);
unsigned int mazokuParcelCreateMemBBacked(const void* src, unsigned int len) {
	return anoParcelCreateMemBBacked(spoofScanTarget((void*) src, len), len);
}

unsigned int (*unityProxy)(int attestationKey, void* src, size_t len);
unsigned int mazokuProxy(int attestationKey, void* src, size_t len) {
	return unityProxy(attestationKey, spoofScanTarget((void*) src, len), len);
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

void init_callback(uintptr_t start, uintptr_t end, const char* perms,
					 off_t offset, const char* dev,
					 unsigned int inode, const char* file)
{
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
	while (!hasGameSafe && !hasSpoofedLibs) {
		maps_pairs(init_callback);
		nanosleep(&loopnap, nullptr);
	}
	while ((end = spoofTargetLibs.find('\n')) != std::string::npos) {
		spoofedLib = spoofTargetLibs.substr(start, end - start);
		spoofedLibs[spoofedLib];
		spoofTargetLib(spoofedLib);
		start = end + 1;
	}
	spoofedLib = spoofTargetLibs.substr(start, end - start);
	spoofedLibs[spoofedLib];
	spoofTargetLib(spoofedLib);
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