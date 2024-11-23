/* Copyright 2022-2023 John "topjohnwu" Wu
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <thread>

#include "zygisk.hpp"

#include "core.cpp"
#include "emoji.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

class Mazoku : public zygisk::ModuleBase {
public:
	bool isMazokuTarget = false;

    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        // Use JNI to fetch our process name
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
		const char *app_data = env->GetStringUTFChars(args->app_data_dir, nullptr);
        preSpecialize(process, app_data);
        env->ReleaseStringUTFChars(args->nice_name, process);
		env->ReleaseStringUTFChars(args->app_data_dir, app_data);
    }

	void postAppSpecialize(const AppSpecializeArgs *args) override {
		postSpecialize();
	}

    void preServerSpecialize(ServerSpecializeArgs *args) override {
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api;
    JNIEnv *env;

    void preSpecialize(const char *process, const char *app_data) {
		if (!strcmp(process, "com.activision.callofduty.shooter")) {
			int pid = getpid();
			int fd = api->connectCompanion();
			if (fd == -1) {
				api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
				LOGE("Cannot obtain valid file descriptor for companion!");
				return;
			}
			write(fd, &pid, sizeof(pid));
			writestr(fd, (char*) process);
			read(fd, &isMazokuTarget, sizeof(isMazokuTarget));
			if (!isMazokuTarget)
				api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
			close(fd);
		}
    }

	void postSpecialize() const {
		if (isMazokuTarget)
			std::thread(mazoku_runtime).detach();
		else
			api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
	}

};

static void MazokuService(int fd)
{
	int pid;
	char* procname;
	char mazProp[] = "/data/adb/modules/zygisk_mazoku/module.prop";
	char update[] = "/data/adb/modules/zygisk_mazoku/update";
	char disable[] = "/data/adb/modules/zygisk_mazoku/disable";
	char spoof_target_libs[] = "/data/adb/mazoku/spoof_target_libs.txt";
	bool enable = true;
	std::string oldDesc(getDescription(mazProp));
	read(fd, &pid, sizeof(pid));
	procname = readstr(fd);
	if (!access(update, F_OK) || !access(disable, F_OK)) {
		enable = false;
		write(fd, &enable, sizeof(enable));
		updateDescription(mazProp, emoji::emojize("[:x: Mazoku is disabled/updated!] ").c_str());
		return;
	} else
		write(fd, &enable, sizeof(enable));
	LOGI("oldDesc.length() = [%zu]", oldDesc.length());
	if (oldDesc.length() == 93)
		ud:
		updateDescription(mazProp, (std::string(emoji::emojize("[:yum:  Mazoku is working!] (")) + std::string(procname) + ":" + std::to_string(pid) + ") " + oldDesc).c_str());
	else {
		oldDesc = "当月光洒在银色的湖面上，一条道路会为那些决心前行的人显现出来。";
		goto ud;
	}
	free(procname);
}

REGISTER_ZYGISK_MODULE(Mazoku)
REGISTER_ZYGISK_COMPANION(MazokuService)