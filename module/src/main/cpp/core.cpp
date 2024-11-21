
#include <android/log.h>

#define LOG_ON true
#define LOGD(...) if (LOG_ON) __android_log_print(ANDROID_LOG_DEBUG, "mazoku", __VA_ARGS__)
#define LOGE(...) if (LOG_ON) __android_log_print(ANDROID_LOG_ERROR, "mazoku", __VA_ARGS__)
#define LOGI(...) if (LOG_ON) __android_log_print(ANDROID_LOG_INFO, "mazoku", __VA_ARGS__)

#include "utils.cpp"
#include <string>
#include <sys/stat.h>

using namespace std;

typedef struct {
	void*	reserved0;
	void*	reserved1;
	void*	reserved2;
	void*	begin;
	void*	finish;
} Aeo;

typedef struct {
	int32_t	id;
	int 	unk_a;
	void*	code;
	int 	verdict;
	int		code_size;
	int 	block_size;
	bool	unk_b;
	int 	unk_c;
	int 	unk_d;
	int 	unk_e;
	int 	unk_f;
} Eo;

bool hasGameSafe = false;
Aeo* (*anoGetExternalObjects)();
int (*anoCreateSWBackedIntegrity)(int, unsigned char *, size_t);

void mazoku_callback(uintptr_t start, uintptr_t end, const char* perms,
					 off_t offset, const char* dev,
					 unsigned int inode, const char* file)
{
	if (strstr(file, "/libanogs.so") && is_elf(start)) {
		hasGameSafe = true;
		anoGetExternalObjects = (Aeo* (*)()) (start + 0x29AF48);
		anoCreateSWBackedIntegrity = (int (*)(int, unsigned char *, size_t)) (start + 0x28D57C);
	}
}

void mazoku_runtime()
{
	struct timespec loopnap{};
	loopnap.tv_sec = 1;
	loopnap.tv_nsec = 0;
	while (!hasGameSafe) {
		maps_pairs(mazoku_callback);
		nanosleep(&loopnap, nullptr);
	}
	LOGI("anoGetExternalObjects [%p]", anoGetExternalObjects);
	LOGI("anoCreateSWBackedIntegrity [%p]", anoCreateSWBackedIntegrity);
	Aeo* anoExtObjs = anoGetExternalObjects();
	if (anoExtObjs) {
		LOGI("Aeo [%p]", anoExtObjs);
		for (Eo* obj = (Eo*) *(uintptr_t*) anoExtObjs->begin; (uintptr_t) obj == (uintptr_t) *(uintptr_t*) anoExtObjs->finish; obj += sizeof(Eo*)) {
			LOGI("extobj(%x) = {", obj->id);
			LOGI("\tunknown[a](int)  = %d", obj->unk_a);
			LOGI("\tcode(void*)      = %p", obj->code);
			LOGI("\tverdict(hex)     = %X", obj->verdict);
			LOGI("\tcode_size(int)   = %d", obj->code_size);
			LOGI("\tunknown[b](bool) = %d", obj->unk_b);
			LOGI("\tunknown[c](int)  = %d", obj->unk_c);
			LOGI("\tunknown[d](int)  = %d", obj->unk_d);
			LOGI("\tunknown[e](int)  = %d", obj->unk_e);
			LOGI("\tunknown[f](int)  = %d", obj->unk_f);
			LOGI("}");
		}
	} else {
		LOGE("nulled Aeo found, exiting..");
	}
}