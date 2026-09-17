#pragma once

/* Minimal compiler port used by Tailcat's in-process NO_SYS lwIP stack. */
#ifdef _WIN32
#define LWIP_NO_UNISTD_H 1
#endif

#ifdef __cplusplus
extern "C" {
#endif
unsigned int tailcat_lwip_rand(void);
#ifdef __cplusplus
}
#endif

#define LWIP_RAND() ((unsigned int)tailcat_lwip_rand())
