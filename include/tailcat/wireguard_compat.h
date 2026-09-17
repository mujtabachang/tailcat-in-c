#pragma once

/* wireguard-lwip uses GCC's packed attribute spelling in its public header.
 * Its WireGuard message layouts are naturally packed (4-byte header/indexes
 * followed by byte arrays), so MSVC can safely ignore that spelling. Static
 * size assertions in the C++ wrapper verify the wire layouts on every build.
 */
#ifdef _MSC_VER
#ifndef __attribute__
#define __attribute__(x)
#endif
#endif
