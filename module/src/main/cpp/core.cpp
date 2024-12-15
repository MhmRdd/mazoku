
#include <android/log.h>

#define LOG_ON true
#define LOGD(...) if (LOG_ON) __android_log_print(ANDROID_LOG_DEBUG, "mazoku", __VA_ARGS__)
#define LOGE(...) if (LOG_ON) __android_log_print(ANDROID_LOG_ERROR, "mazoku", __VA_ARGS__)
#define LOGW(...) if (LOG_ON) __android_log_print(ANDROID_LOG_WARN, "mazoku", __VA_ARGS__)
#define LOGI(...) if (LOG_ON) __android_log_print(ANDROID_LOG_INFO, "mazoku", __VA_ARGS__)
#define LOGF(...) if (LOG_ON) __android_log_print(ANDROID_LOG_FATAL, "mazoku", __VA_ARGS__)

#include "utils.cpp"
#include <string>
#include <cctype>
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
#include <filesystem>
#include <dlfcn.h>
#include <dobby.h>

namespace fs = std::filesystem;

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

std::string spoofDir;
std::map<std::string, char> spoofFromFiles;
std::map<std::string, std::set<std::tuple<uintptr_t, uintptr_t, size_t>>> spoofedLibs;
std::map<std::string, uintptr_t> handles;

char chkSpoofLibByFiles(std::string& lib) {
	if (lib.empty())
		return 0;
	char token = lib.back();
	switch (token) {
		case '?':
			lib.pop_back();
			if (!spoofDir.empty()) {
				spoofFromFiles[lib] = token;
				return token;
			} else {
				LOGE("Unexpected empty spoofing directory, disabling HW backed proof!");
				return 0;
			}
			break;
		case '!':
			lib.pop_back();
			if (!spoofDir.empty()) {
				spoofFromFiles[lib] = token;
				return token;
			} else {
				LOGF("Unable to continue without HW backed proof (strict mode enabled).");
				kill(getpid(), SIGKILL);
				return 0;
			}
			break;
		default:
			break;
	}
	auto it = spoofFromFiles.find(lib);
	if (it != spoofFromFiles.end())
		return it->second;
	return 0;
}

bool writeTargetLibByFiles(std::string& lib, int index, void* src, size_t len) {
	if (!chkSpoofLibByFiles(lib))
		return false;
	std::string spoofedBlock = spoofDir + lib + "." + std::to_string(index);
	std::ofstream vmblock(spoofedBlock, std::ios::binary | std::ios::ate);
	if (!vmblock.is_open()) {
		LOGE("Unable to open `%s`!", spoofedBlock.c_str());
		return false;
	}
	vmblock.write(reinterpret_cast<char*>(src), len);
	if (vmblock) {
		LOGI("Created hardware backed proof `%s`.", lib.c_str());
		vmblock.close();
		return true;
	} else {
		LOGE("Unable to read backed `%s`!", lib.c_str());
		return false;
	}
}

bool readTargetLibByFiles(std::string& lib, int index, void* cpy, size_t len) {
	if (!chkSpoofLibByFiles(lib))
		return false;
	std::string spoofedBlock = spoofDir + lib + "." + std::to_string(index);
	if (fs::is_regular_file(spoofedBlock)) {
		std::ifstream vmblock(spoofedBlock, std::ios::binary | std::ios::ate);
		if (!vmblock.is_open()) {
			LOGE("Unable to open `%s`!", spoofedBlock.c_str());
			return false;
		}
		auto vmlen = vmblock.tellg();
		if (len != (size_t) vmlen) {
			LOGE("Backed file size mismatches memory blocks!");
			vmblock.close();
			fs::remove(spoofedBlock);
			return false;
		}
		vmblock.seekg(0, std::ios::beg);
		vmblock.read(reinterpret_cast<char*>(cpy), vmlen);
		if (vmblock) {
			LOGI("Loaded hardware backed proof `%s`.", lib.c_str());
			vmblock.close();
			return true;
		} else {
			LOGE("Unable to read backed `%s`!", lib.c_str());
			return false;
		}
	} else {
		LOGW("No such hardware backed proof of `%s` was found.", lib.c_str());
		fs::remove(spoofedBlock);
		return false;
	}
}

bool spoofTargetLib(std::string& lib) {
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
		int index = 1;
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
			if ((perms == "r--p" || perms == "r-xp") && file.ends_with("/" + lib)) {
				size_t len = end - start;
				bool isFoundInDenylist = false;
				for (const auto& deny : it->second) {
					if (std::get<0>(deny) == start && std::get<0>(deny) + std::get<2>(deny) == end) {
						isFoundInDenylist = true;
						break;
					}
				}
				if (isFoundInDenylist)
					continue;
				void *vmcpy = malloc(len);
				if (!vmcpy) {
					LOGE("Unable to allocate memory! (size = [%zu])", len);
					continue;
				} else if (perms == "r--p") {
					memcpy(vmcpy, (void *) start, len);
					mprotect(vmcpy, len, PROT_READ);
					index--;
				} else {
					uint8_t* backedBlock = fsha256(std::string(spoofDir + lib + "." + std::to_string(index) + ".sha256").c_str());
					if (!backedBlock && chkSpoofLibByFiles(lib) == '!') {
						free(vmcpy);
						LOGI("Ignoring `%s`(%d) [%p-%p] (strict mode enabled)", lib.c_str(), index,
							 (void *) start, (void *) end);
						continue;
					} else if (!readTargetLibByFiles(lib, index, vmcpy, len)) {
						memcpy(vmcpy, (void *) start, len);
						writeTargetLibByFiles(lib, index, vmcpy, len);
					}
					if (backedBlock) {
						uint8_t* hashedBlock = sha256(vmcpy, len);
						if (!csha256(backedBlock, hashedBlock)) {
							LOGE("Failed to verify `%s.%d`!", lib.c_str(), index);
							kill(getpid(), SIGKILL);
						} else {
							LOGI("Verified `%s.%d`", lib.c_str(), index);
						}
						free(hashedBlock);
						free(backedBlock);
					}
				}
				mprotect(vmcpy, len, PROT_READ);
				it->second.emplace(start, (uintptr_t) vmcpy, len);
				isAddedAtLeastOnce = true;
				LOGI("Created software backed copy of `%s`(%d) [%p-%p]!", lib.c_str(), index,
					 (void *) start, (void *) end);
				index++;
			}
		}
	}
	return isAddedAtLeastOnce;
}

extern "C" void *spoofScanTarget(void *at, size_t len) {
	char* lib = wherethis(at);
	if (lib) {
		for (const auto& [slib, denylist] : spoofedLibs) {
			if (lib == slib) {
				for (const auto& deny : denylist) {
					if (std::get<0>(deny) <= (uintptr_t) at && std::get<0>(deny) + std::get<2>(deny) >= (uintptr_t) at + len) {
						//LOGI("`%s` was found in spoofed targets!", slib.c_str());
						//LOGI("Scan[(%s + %p) (size = [%zu]) -> [%p (size = [%zu])]", lib, (void*) ((uintptr_t) at - std::get<0>(deny)), len, (void*) std::get<1>(deny), std::get<2>(deny));
						return (void*) (std::get<1>(deny) + ((uintptr_t) at - std::get<0>(deny)));
					}
				}
			}
		}
		//LOGI("`%s`[%p](size: %zu) was not found in spoofed target libs.", lib, at, len);
	}
	free(lib);
	return at;
}

std::map<void*, std::pair<void*, size_t>> safeAllocs;

void srealloc(void** ptr, size_t len) {
	void* src = *ptr;
	void* cpy = malloc(len);
	memcpy(cpy, src, len);
	safeAllocs[cpy] = {src, len};
	*ptr = cpy;
}

void sdealloc(void** ptr) {
	void* cpy = *ptr;
	for (const auto& orig : safeAllocs) {
		if (orig.first == cpy) {
			memcpy(orig.second.first, cpy, orig.second.second);
			*ptr = orig.second.first;
			safeAllocs.erase(orig.first);
			free(orig.first);
			return;
		}
	}
}

void mazoku_dzjm();

Aeo* (*anoGetExternalObjects)();
unsigned int (*anoCreateSWBackedIntegrity)(int, unsigned char *, size_t) = nullptr;
unsigned int (*anoCreateMemoryHashed)(const void*, unsigned int) = nullptr;
void* (*anoTreaters)() = nullptr;
void* (*anoParam)(void*, unsigned int) = nullptr;
ssize_t (*process_vm_readv)(pid_t, const struct iovec*, unsigned long, const struct iovec*, unsigned long, unsigned long) = nullptr;

ssize_t mazoku_vm_readv(pid_t pid, const struct iovec* local_iov, unsigned long liovcnt, const struct iovec* remote_iov, unsigned long riovcnt, unsigned long flags) {
	struct iovec mazoku_iov{};
	mazoku_iov.iov_base = spoofScanTarget(remote_iov->iov_base, remote_iov->iov_len);
	if (mazoku_iov.iov_base != remote_iov->iov_base) {
		//LOGI("[mazoku_vm] Futile scan replaced [%p -> %p]", remote_iov->iov_base, mazoku_iov.iov_base);
		return process_vm_readv(pid, local_iov, liovcnt, &mazoku_iov, riovcnt, flags);
	} else
		return process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

int (*anoCustomCall)(void*) = nullptr;
int mazokuCustomCall(void* liteDZJM) {
	void* dzjm = (void*) ((uintptr_t) liteDZJM + 64);
	void* dzplt = (void*) *(uintptr_t*) anoParam(dzjm, 0LL);
	void* dzsc = (void*) *(uintptr_t *) (uintptr_t) dzplt;
	if (dzsc == process_vm_readv) {
		*(uintptr_t*) dzplt = reinterpret_cast<uintptr_t>(mazoku_vm_readv);
		LOGI("Updated dmabuf[%p -> %p] to mazoku_vm_***[%p]", dzplt, dzsc, mazoku_vm_readv);
		int result = anoCustomCall(liteDZJM);
		*(uintptr_t*) dzplt = reinterpret_cast<uintptr_t>(dzsc);
		return result;
	}
	return anoCustomCall(liteDZJM);
}

unsigned int mazokuCreateMemoryHashed(const void* src, unsigned int len) {
	//LOGI("[MemoryHashed]: %p (size = [%u])", src, len);
	return anoCreateMemoryHashed(spoofScanTarget((void*) src, len), len);
}

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
	//LOGI("[UnityProxy]: attKey [%d]  target [%p]  size [%zu]", attestationKey, src, len);
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
			LOGI("Updated proxy[%p -> %p] to mazokuProxy[%p].", (void *) proxyloc, (void *) proxy,
				 mazokuProxy);
			*(uintptr_t *) proxyloc = reinterpret_cast<uintptr_t>(mazokuProxy);
		} else {
			LOGE("Unknown proxy[%p]!", (void*) proxy);
		}
		unsigned int result = anoParcelProxy(unityNS);
		*(uintptr_t*) proxyloc = proxy;
		return result;
	} else {
		LOGE("Unable to locate proxy function from libunity.so!");
		return anoParcelProxy(unityNS);
	}
}


void* (*anoParcelCreateMemCBacked)(void*) = nullptr;
void* mazokuParcelCreateMemCBacked(void* vold) {
	if (!anoCreateMemoryHashed) {
		void* pltmh = (void*) (((uintptr_t *) vold)[1] + 136LL);
		anoCreateMemoryHashed = reinterpret_cast<unsigned int (*)(const void *, unsigned int)>(*(uintptr_t*) pltmh);
		LOGI("anoCreateMemoryHashed [%p]", anoCreateMemoryHashed);
	}
	return anoParcelCreateMemCBacked(vold);
}

void* (*anoParcelEnforceMemCBacked)(void*, void*, size_t) = nullptr;
void* mazokuParcelEnforceMemCBacked(void* backed, void* nonbacked, size_t len) {
	return anoParcelEnforceMemCBacked(spoofScanTarget(backed, len), spoofScanTarget(nonbacked, len), len);
}

void init_callback(uintptr_t start, uintptr_t end, const char* perms,
				   off_t offset, const char* dev,
				   unsigned int inode, const char* file)
{
	if (strstr(file, "/libanogs.so") && is_elf(start)) {
		handles["libanogs.so"] = start;
		hasGameSafe = true;
		anoGetExternalObjects = (Aeo* (*)()) (start + 0x29AF48);
		anoCreateSWBackedIntegrity = (unsigned int(*)(int, unsigned char *, size_t)) (start + 0x28D57C);
		anoTreaters = (void *(*)()) (start + 0x264588);
		anoCustomCall = (int (*)(void*)) (start + 0x25A34C);
		anoParam = (void *(*)(void*, unsigned int)) (start + 0x1D6D80);
	}
}

std::vector<unsigned int> spid = {
		0x65ed4aa9,
		0x29e97f13,
		0x8852e992,
		0xab060544
};

std::vector<unsigned int> sped = {};

enum SPTAG {
	SPT_MEMHASH_A,
	SPT_MEMHASH_B,
	SPT_PARCEL,
	SPT_MEMHASH_C
};

bool seekpatch(unsigned int id, void* code, int size)
{
	long index;
	auto it = std::find(spid.begin(), spid.end(), id);
	if (it != spid.end() && std::find(sped.begin(), sped.end(), id) == sped.end()) {
		index = std::distance(spid.begin(), it);
	} else
		return false;
	//void* cpy = malloc(size);
	//memcpy(cpy, code, size);
	//mprotect(cpy, size, PROT_READ);
	//spoofedLibs["[anon:objects_external_alloc]"].emplace((uintptr_t) code, (uintptr_t) cpy, size);
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
		case SPT_MEMHASH_C:
			/*while (!anoCreateMemoryHashed) {
				anoCreateMemoryHashed = reinterpret_cast<unsigned int (*)(const void *, unsigned int)>(*(uintptr_t*)((uintptr_t) code + 4840));
				nanosleep(&loopnap, nullptr);
			}
			if (anoCreateMemoryHashed != reinterpret_cast<unsigned int (*)(const void *, unsigned int)>(*(uintptr_t*)((uintptr_t) code + 4840))) {
				LOGE("Unknown memory hashing function!");
				return false;
			}*/
			A64HookFunction((void*) (uintptr_t) code, (void*) mazokuParcelCreateMemCBacked, (void**) &anoParcelCreateMemCBacked);
			*(uint32_t*)((uintptr_t) code + 1344) = 0xD503201Fu;		// NOP
			*(uintptr_t*)((uintptr_t) code + 4840) = reinterpret_cast<uintptr_t>(mazokuCreateMemoryHashed);
			A64HookFunction((void*) ((uintptr_t) code + 1660), (void*) mazokuParcelEnforceMemCBacked, (void**) &anoParcelEnforceMemCBacked);
			//*(uint32_t*)((uintptr_t) code + 3808 + 4) = 0xD503201Fu;
			//A64HookFunction((void*) ((uintptr_t) code + 3808), (void*) mazokuParcelCreateMemCBacked, (void**) &anoParcelCreateMemCBacked);
			//*(uint32_t*)((uintptr_t) code + 3808) = 0x58000048u;		// LDR X8, #0x8
			//*(uint32_t*)((uintptr_t) code + 3808 + 4) = 0xD61F0100u;	// BR X8
			//anoParcelCreateMemCBacked = (void (*)()) ((uintptr_t) code + 3808 + 16); // Continuous function call
			//*(uintptr_t*)((uintptr_t) code + 3808 + 8) = reinterpret_cast<uintptr_t>(mazokuParcelCreateMemCBacked); // Set hook address
			break;
		default:
			return false;
	}
	sped.push_back(id);
	return true;
}

int mazoku_dzjm(void* trptr) {
	if (trptr) {
		void* handler = (void*) *(uintptr_t *) ((uintptr_t) trptr + 48);
		if (handler) {
			if ((int (*)(void*)) *(uintptr_t *) ((uintptr_t) handler + 0x28) == anoCustomCall) {
				LOGI("Redirected DZJM's custom caller.");
				LOGI("anoCustomCall [%p -> %p] -> mazokuCustomCall[%p]", (void*) ((uintptr_t) handler + 0x28), anoCustomCall, mazokuCustomCall);
				*(uintptr_t*) ((uintptr_t) handler + 0x28) = reinterpret_cast<uintptr_t>(mazokuCustomCall);
				mprotect((void*) (handles["libanogs.so"] + 0x543000), 0x1000, PROT_READ | PROT_WRITE);
				*(uintptr_t*) (handles["libanogs.so"] + 0x543610) = reinterpret_cast<uintptr_t>(mazokuCustomCall);
				mprotect((void*) (handles["libanogs.so"] + 0x543000), 0x1000, PROT_READ);
				return 1;
			} else if ((int (*)(void*)) *(uintptr_t *) ((uintptr_t) handler + 0x28) == mazokuCustomCall) {
				LOGI("Unshare mazoku custom caller.");
				*(uintptr_t*) ((uintptr_t) handler + 0x28) = reinterpret_cast<uintptr_t>(anoCustomCall);
				mprotect((void*) (handles["libanogs.so"] + 0x543000), 0x1000, PROT_READ | PROT_WRITE);
				*(uintptr_t*) (handles["libanogs.so"] + 0x543610) = reinterpret_cast<uintptr_t>(anoCustomCall);
				mprotect((void*) (handles["libanogs.so"] + 0x543000), 0x1000, PROT_READ);
				return 0;
			} else
				LOGW("Unknown custom call, abort.");
		} else
			LOGE("Unable to obtain DZJM handlers!");
	} else
		LOGE("Unable to obtain DZJM treaters!");
	return -1;
}

void mazoku_runtime2(void* trptr) {
	struct timespec loopnap{};
	loopnap.tv_sec = 0;
	loopnap.tv_nsec = 1000000;
	while (mazoku_dzjm(trptr) == -1) nanosleep(&loopnap, nullptr);
}

void mazoku_runtime(const std::string& spoofTargetLibs, const std::string& process)
{
	std::string app_data = "/data/data/" + process;
	LOGI("app_data_dir [%s]", app_data.c_str());
	if (!app_data.empty()) {
		if (fs::is_directory(app_data + "/files")) {
			spoofDir = app_data + "/files/.mazoku";
			if (!fs::is_directory(spoofDir)) {
				fs::remove(spoofDir);
				fs::create_directory(spoofDir);
			}
			spoofDir += "/";
		} else
			LOGE("`%s` is not directory!", (app_data + "/files").c_str());
	} else
		LOGE("`app_data_dir` is undefined/empty!");
	struct timespec loopnap{};
	loopnap.tv_sec = 1;
	loopnap.tv_nsec = 0;
	ssize_t start = 0, end;
	std::istringstream stlream(spoofTargetLibs);
	std::string spoofedLib;
	void* handle = dlopen("libc.so", RTLD_LAZY);
	process_vm_readv = (ssize_t (*)(pid_t, const struct iovec*, unsigned long, const struct iovec*, unsigned long, unsigned long)) dlsym(handle, "process_vm_readv");
	if (!process_vm_readv) {
		LOGE("Cannot resolve dependencies!");
		return;
	}
	dlclose(handle);
	LOGI("spoofTargetLibs [%s]", spoofTargetLibs.c_str());
	while (!hasGameSafe && !hasSpoofedLibs) {
		maps_pairs(init_callback);
		nanosleep(&loopnap, nullptr);
	}
	while (std::getline(stlream, spoofedLib)) {
		if (!spoofedLib.empty()) {
			chkSpoofLibByFiles(spoofedLib);
			spoofedLibs[spoofedLib];
			spoofTargetLib(spoofedLib);
		}
	}
	LOGI("anoTreaters [%p]", anoTreaters);
	LOGI("anoGetExternalObjects [%p]", anoGetExternalObjects);
	LOGI("anoCreateSWBackedIntegrity [%p]", anoCreateSWBackedIntegrity);
	void* anoDZJMTrts = anoTreaters();
	if (anoDZJMTrts)
		std::thread(mazoku_runtime2, anoDZJMTrts).detach();
	else {
		LOGE("nulled DZJM found, exiting..");
		return;
	}
	Aeo* anoExtObjs = anoGetExternalObjects();
	if (anoExtObjs) {
		LOGI("Aeo [%p]", anoExtObjs);
		size_t len, updlen;
		loopnap.tv_sec = 0;
		loopnap.tv_nsec = 1000;
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