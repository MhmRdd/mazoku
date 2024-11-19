
#include <stdbool.h>
#include <android/log.h>

#define LOG_ON false
#define LOGD(...) if (LOG_ON) __android_log_print(ANDROID_LOG_DEBUG, "mazoku", __VA_ARGS__)

bool mazoku_init(const char* process)
{
	return false;
}