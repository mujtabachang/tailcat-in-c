#pragma once

/* Minimal compiler port used while Tailcat embeds lwIP as a userspace stack. */
#ifdef _WIN32
#define LWIP_NO_UNISTD_H 1
#endif
