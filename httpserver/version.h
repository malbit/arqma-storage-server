#pragma once

#include "arqma_logger.h"

#include <iostream>

#ifndef STORAGE_SERVER_VERSION_STRING
#define STORAGE_SERVER_VERSION_STRING "1.0.5"
#endif

#ifndef STORAGE_SERVER_GIT_HASH_STRING
#define STORAGE_SERVER_GIT_HASH_STRING "?"
#endif

#ifndef STORAGE_SERVER_BUILD_TIME
#define STORAGE_SERVER_BUILD_TIME "?"
#endif

static void print_version() {
    ARQMA_LOG(info,
             "Arqma Storage Server v{}\n git commit hash: {}\n build time: {}",
             STORAGE_SERVER_VERSION_STRING, STORAGE_SERVER_GIT_HASH_STRING,
             STORAGE_SERVER_BUILD_TIME);
}
