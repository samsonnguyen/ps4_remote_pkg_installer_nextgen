/*
 * Remote PKG Installer NextGen
 * Copyright (c) 2025-present AldySan and contributors.
 * Licensed under the GNU General Public License v3.0. See LICENSE for details.
 *
 * BGFT download wrappers: task registration with legacy semantics
 * (already-installed reports task id -1 as success), control ops and
 * progress snapshots.
 */
#include "bgft.h"
#include "log.h"
#include "modules.h"
#include "diag.h"

#include <pthread.h>
#include <stdio.h>

#include <orbis/UserService.h>
#include <orbis/_types/sysmodule.h>

#include <stdlib.h>
#include <string.h>

/*
 * BGFT ServiceInt backend. Signatures follow the app-facing BGFT ABI used
 * by ps4-ezremote-client for registration and task operations.
 * These are intentionally declared locally: src/bgft.h exposes a separate
 * app-facing API, while the SDK header has overlapping type definitions.
 */
extern int sceBgftServiceIntInit(SceBgftInitParams *params);
extern int sceBgftServiceIntTerm(void);
extern int sceBgftServiceIntDownloadRegisterTask(SceBgftDownloadParam *params,
                                                SceBgftTaskId *task_id);
extern int sceBgftServiceIntDebugDownloadRegisterPkg(SceBgftDownloadParam *params,
                                                     SceBgftTaskId *task_id);
extern int sceBgftServiceIntDownloadStartTask(SceBgftTaskId task_id);
extern int sceBgftServiceIntDownloadPauseTask(SceBgftTaskId task_id);
extern int sceBgftServiceIntDownloadResumeTask(SceBgftTaskId task_id);
extern int sceBgftServiceIntDownloadStopTask(SceBgftTaskId task_id);
extern int sceBgftServiceIntDownloadUnregisterTask(SceBgftTaskId task_id);
extern int sceBgftServiceIntDownloadReregisterTaskPatch(SceBgftTaskId old_task_id,
                                                       SceBgftTaskId *new_task_id);
extern int sceBgftServiceDownloadGetProgress(SceBgftTaskId task_id,
                                            SceBgftTaskProgress *progress);
extern int sceBgftServiceDownloadFindTaskByContentId(
    const char *content_id, enum SceBgftTaskSubType sub_type,
    SceBgftTaskId *task_id);

static void bgft_diag_ret(const char *operation, int ret)
{
    char message[96];
    snprintf(message, sizeof(message), "serviceint-%s-ret-%08X", operation,
             (unsigned)ret);
    diag_note(message);
}

static bool s_initialized = false;
static SceBgftInitParams s_init_params;

bool bgft_init(void)
{
    int ret;

    if (s_initialized) {
        return true;
    }

    if (!modules_is_loaded(ORBIS_SYSMODULE_INTERNAL_BGFT)) {
        LOG_WARN("bgft: module unavailable; installs disabled");
        return false;
    }

    memset(&s_init_params, 0, sizeof(s_init_params));
    s_init_params.heapSize = SCE_BGFT_HEAP_SIZE;
    s_init_params.heap = (uint8_t*)malloc(s_init_params.heapSize);
    if (!s_init_params.heap) {
        LOG_ERROR("bgft: out of memory for heap");
        return false;
    }
    memset(s_init_params.heap, 0, s_init_params.heapSize);

    diag_note("serviceint-backend-before-init");
    {
        int (*volatile init_fn)(SceBgftInitParams *) = sceBgftServiceIntInit;
        if (!init_fn) {
            diag_note("serviceint-backend-init-import-null");
            free(s_init_params.heap);
            s_init_params.heap = NULL;
            s_init_params.heapSize = 0;
            return false;
        }
        ret = init_fn(&s_init_params);
    }
    bgft_diag_ret("backend-init", ret);
    if (ret != 0) {
        LOG_ERROR("sceBgftServiceIntInit failed: 0x%08X", ret);
        free(s_init_params.heap);
        s_init_params.heap = NULL;
        s_init_params.heapSize = 0;
        return false;
    }

    s_initialized = true;

    /* Where the system libraries landed, so a crash journal rip such as
     * 0x800004414 can be attributed to a module (and a nearby export). */
    {
        extern int* __error(void);
        diag_notef("probe-addr-kernel-mutex_lock-%p-join-%p",
                   (void*)pthread_mutex_lock, (void*)pthread_join);
        diag_notef("probe-addr-kernel-create-%p-detach-%p-self-%p-error-%p",
                   (void*)pthread_create, (void*)pthread_detach,
                   (void*)pthread_self, (void*)__error);
        diag_notef("probe-addr-kernel-condwait-%p-condbcast-%p-unlock-%p",
                   (void*)pthread_cond_wait, (void*)pthread_cond_broadcast,
                   (void*)pthread_mutex_unlock);
        diag_notef("probe-addr-kernel-attrinit-%p-setstack-%p-mutexinit-%p",
                   (void*)pthread_attr_init, (void*)pthread_attr_setstacksize,
                   (void*)pthread_mutex_init);
    }
    diag_notef("probe-addr-bgft-register-%p-registerpkg-%p-progress-%p",
               (void*)sceBgftServiceIntDownloadRegisterTask,
               (void*)sceBgftServiceIntDebugDownloadRegisterPkg,
               (void*)sceBgftServiceDownloadGetProgress);
    return true;
}

void bgft_fini(void)
{
    if (!s_initialized) {
        return;
    }

    bgft_diag_ret("backend-term", sceBgftServiceIntTerm());

    free(s_init_params.heap);
    memset(&s_init_params, 0, sizeof(s_init_params));

    s_initialized = false;
}

int bgft_get_user_id(void)
{
    int user_id = -1;
    int ret;

    if (!modules_is_loaded(ORBIS_SYSMODULE_INTERNAL_USER_SERVICE)) {
        LOG_WARN("bgft: user service unavailable; cannot resolve the user");
        return -1;
    }

    ret = sceUserServiceGetForegroundUser(&user_id);
    if (ret != 0) {
        LOG_ERROR("sceUserServiceGetForegroundUser failed: 0x%08X", ret);
        return -1;
    }
    return user_id;
}

static bool is_duplicate_error(int ret)
{
    return ret == (int)SCE_BGFT_ERROR_TASK_DUPLICATED ||
           ret == (int)SCE_BGFT_ERROR_CONTENT_ALREADY_DOWNLOADING;
}

/*
 * Registration was refused because BGFT already holds a task for this
 * content id. Find that task, record what state it is in (diag journal and
 * activity log), and release it when it has already failed so the caller can
 * register once more. A task that has not failed is left alone: it may be a
 * download the user still wants, and they can cancel it from the PS4
 * Downloads list.
 *
 * Returns true only when a failed task was unregistered and a retry makes
 * sense. *existing_task_id receives the task found, or -1.
 */
static bool bgft_release_failed_duplicate(const char* content_id,
                                          const char* package_type,
                                          bool is_patch, int* existing_task_id)
{
    int candidates[3];
    int count = 0;
    int i;
    int found = SCE_BGFT_INVALID_TASK_ID;
    int found_sub_type = 0;
    char note[128];

    *existing_task_id = SCE_BGFT_INVALID_TASK_ID;

    /* Most likely sub type first, then the other game sub types. */
    if (is_patch) {
        candidates[count++] = SCE_BGFT_TASK_SUB_TYPE_GAME_PATCH;
    } else if (package_type && strcmp(package_type, "PS4AC") == 0) {
        candidates[count++] = SCE_BGFT_TASK_SUB_TYPE_GAME_AC;
    } else {
        candidates[count++] = SCE_BGFT_TASK_SUB_TYPE_GAME;
    }
    if (candidates[0] != SCE_BGFT_TASK_SUB_TYPE_GAME)
        candidates[count++] = SCE_BGFT_TASK_SUB_TYPE_GAME;
    if (candidates[0] != SCE_BGFT_TASK_SUB_TYPE_GAME_AC)
        candidates[count++] = SCE_BGFT_TASK_SUB_TYPE_GAME_AC;
    if (count < 3 && candidates[0] != SCE_BGFT_TASK_SUB_TYPE_GAME_PATCH)
        candidates[count++] = SCE_BGFT_TASK_SUB_TYPE_GAME_PATCH;

    for (i = 0; i < count; ++i) {
        int id = SCE_BGFT_INVALID_TASK_ID;
        int find_error = 0;
        if (bgft_find_task(content_id, candidates[i], &id, &find_error) && id >= 0) {
            found = id;
            found_sub_type = candidates[i];
            break;
        }
    }

    if (found < 0) {
        diag_note("serviceint-dup-not-found");
        LOG_ERROR("bgft: %s is already registered but no matching task was found; "
                  "cancel it in Notifications > Downloads, or restart the PS4",
                  content_id);
        return false;
    }

    *existing_task_id = found;
    {
        SceBgftTaskProgress progress;
        int progress_error = 0;
        bool have_progress = bgft_get_progress(found, &progress, &progress_error);

        if (have_progress) {
            snprintf(note, sizeof(note),
                     "serviceint-dup-task-%d-sub-%d-bits-%08X-err-%08X-xfer-%lu-of-%lu",
                     found, found_sub_type, (unsigned)progress.bits,
                     (unsigned)progress.errorResult,
                     (unsigned long)progress.transferredTotal,
                     (unsigned long)progress.lengthTotal);
        } else {
            snprintf(note, sizeof(note),
                     "serviceint-dup-task-%d-sub-%d-progress-ret-%08X",
                     found, found_sub_type, (unsigned)progress_error);
        }
        diag_note(note);

        if (have_progress && progress.errorResult == 0) {
            LOG_ERROR("bgft: %s already has download task %d (%lu/%lu bytes, "
                      "bits 0x%08X); finish or cancel it in Notifications > "
                      "Downloads, then retry",
                      content_id, found,
                      (unsigned long)progress.transferredTotal,
                      (unsigned long)progress.lengthTotal,
                      (unsigned)progress.bits);
            return false;
        }

        LOG_WARN("bgft: releasing failed task %d for %s (error 0x%08X)",
                 found, content_id,
                 have_progress ? (unsigned)progress.errorResult
                               : (unsigned)progress_error);
    }

    {
        int unregister_error = 0;
        if (!bgft_unregister_task(found, &unregister_error)) {
            LOG_ERROR("bgft: could not release task %d: 0x%08X; cancel it in "
                      "Notifications > Downloads, then retry",
                      found, (unsigned)unregister_error);
            return false;
        }
    }
    diag_note("serviceint-dup-released");
    return true;
}

bool bgft_register(const char* content_id, const char* content_url,
                   const char* content_name, const char* icon_path,
                   const char* package_type, const char* package_sub_type,
                   uint64_t package_size, bool is_patch,
                   int* out_task_id, int* error)
{
    SceBgftDownloadParam params;
    SceBgftTaskId task_id = SCE_BGFT_INVALID_TASK_ID;
    int ret;
    int attempt;

    if (!s_initialized) {
        ret = 0x80010002; /* ENXIO-ish */
        goto err;
    }
    if (!content_id || !content_url || !content_name || !package_type) {
        ret = 0x80010016; /* EINVAL */
        goto err;
    }

    memset(&params, 0, sizeof(params));
    params.userId = bgft_get_user_id();
    if (params.userId < 0) {
        ret = 0x80010002;
        goto err;
    }
    params.entitlementType = 5; /* same as the original application */
    params.id = content_id;
    params.contentUrl = content_url;
    params.contentName = content_name;
    params.iconPath = icon_path ? icon_path : "";
    params.playgoScenarioId = "0";
    params.option = SCE_BGFT_TASK_OPT_DISABLE_CDN_QUERY_PARAM;
    params.packageType = package_type;
    params.packageSubType = package_sub_type ? package_sub_type : "";
    params.packageSize = (unsigned long)package_size;

    /* At most one retry, and only after a failed duplicate was released. */
    for (attempt = 0; attempt < 2; ++attempt) {
        int existing = SCE_BGFT_INVALID_TASK_ID;

        task_id = SCE_BGFT_INVALID_TASK_ID;
        diag_note(is_patch ? "serviceint-register-patch" : "serviceint-register-base");
        if (!is_patch) {
            ret = sceBgftServiceIntDownloadRegisterTask(&params, &task_id);
        } else {
            ret = sceBgftServiceIntDebugDownloadRegisterPkg(&params, &task_id);
        }
        bgft_diag_ret("register", ret);
        if (ret == 0) {
            break;
        }
        if (ret == (int)SCE_BGFT_ERROR_SAME_APPLICATION_ALREADY_INSTALLED) {
            /* Legacy behaviour: report success with task id -1. */
            task_id = -1;
            goto done;
        }
        LOG_ERROR("bgft register failed: 0x%08X", ret);
        if (attempt == 0 && is_duplicate_error(ret) &&
            bgft_release_failed_duplicate(content_id, package_type, is_patch,
                                          &existing)) {
            continue;
        }
        goto err;
    }

done:
    if (out_task_id) {
        *out_task_id = (int)task_id;
    }
    return true;

err:
    if (error) {
        *error = ret;
    }
    if (out_task_id) {
        *out_task_id = SCE_BGFT_INVALID_TASK_ID;
    }
    return false;
}

bool bgft_start_task(int task_id, int* error)
{
    int ret;

    if (!s_initialized) {
        if (error) *error = 0x80010002;
        return false;
    }
    ret = sceBgftServiceIntDownloadStartTask((SceBgftTaskId)task_id);
    bgft_diag_ret("start", ret);
    if (ret != 0) {
        if (error) *error = ret;
        return false;
    }
    return true;
}

bool bgft_pause_task(int task_id, int* error)
{
    int ret;

    if (!s_initialized) {
        if (error) *error = 0x80010002;
        return false;
    }
    ret = sceBgftServiceIntDownloadPauseTask((SceBgftTaskId)task_id);
    bgft_diag_ret("pause", ret);
    if (ret != 0) {
        if (error) *error = ret;
        return false;
    }
    return true;
}

bool bgft_resume_task(int task_id, int* error)
{
    int ret;

    if (!s_initialized) {
        if (error) *error = 0x80010002;
        return false;
    }
    ret = sceBgftServiceIntDownloadResumeTask((SceBgftTaskId)task_id);
    bgft_diag_ret("resume", ret);
    if (ret != 0) {
        if (error) *error = ret;
        return false;
    }
    return true;
}

bool bgft_stop_task(int task_id, int* error)
{
    int ret;

    if (!s_initialized) {
        if (error) *error = 0x80010002;
        return false;
    }
    ret = sceBgftServiceIntDownloadStopTask((SceBgftTaskId)task_id);
    bgft_diag_ret("stop", ret);
    if (ret != 0) {
        if (error) *error = ret;
        return false;
    }
    return true;
}

bool bgft_unregister_task(int task_id, int* error)
{
    int ret;

    if (!s_initialized) {
        if (error) *error = 0x80010002;
        return false;
    }
    ret = sceBgftServiceIntDownloadUnregisterTask((SceBgftTaskId)task_id);
    bgft_diag_ret("unregister", ret);
    if (ret != 0) {
        if (error) *error = ret;
        return false;
    }
    return true;
}

bool bgft_reregister_patch(int old_task_id, int* new_task_id, int* error)
{
    SceBgftTaskId task_id = SCE_BGFT_INVALID_TASK_ID;
    int ret;

    if (!s_initialized || !new_task_id) {
        if (error) *error = 0x80010002;
        return false;
    }
    ret = sceBgftServiceIntDownloadReregisterTaskPatch((SceBgftTaskId)old_task_id, &task_id);
    bgft_diag_ret("reregister", ret);
    if (ret != 0) {
        if (error) *error = ret;
        return false;
    }
    *new_task_id = (int)task_id;
    return true;
}

bool bgft_get_progress(int task_id, SceBgftTaskProgress* progress, int* error)
{
    int ret;

    if (!s_initialized || !progress) {
        if (error) *error = 0x80010002;
        return false;
    }
    memset(progress, 0, sizeof(*progress));
    ret = sceBgftServiceDownloadGetProgress((SceBgftTaskId)task_id, progress);
    if (ret != 0) bgft_diag_ret("progress", ret);
    if (ret != 0) {
        if (error) *error = ret;
        return false;
    }
    return true;
}

bool bgft_find_task(const char* content_id, int sub_type, int* task_id, int* error)
{
    SceBgftTaskId id = SCE_BGFT_INVALID_TASK_ID;
    int ret;

    if (!s_initialized || !content_id || !task_id) {
        if (error) *error = 0x80010016;
        return false;
    }
    ret = sceBgftServiceDownloadFindTaskByContentId(
        content_id, (enum SceBgftTaskSubType)sub_type, &id);
    bgft_diag_ret("find", ret);
    if (ret != 0) {
        if (error) *error = ret;
        return false;
    }
    *task_id = (int)id;
    return true;
}
