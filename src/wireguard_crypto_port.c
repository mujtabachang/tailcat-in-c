#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void crypto_zero(void *dest, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)dest;
  while (len-- > 0U) *p++ = 0U;
}

bool crypto_equal(const void *a, const void *b, size_t size) {
  const uint8_t *pa = (const uint8_t *)a;
  const uint8_t *pb = (const uint8_t *)b;
  uint8_t neq = 0U;
  while (size-- > 0U) neq |= (uint8_t)(*pa++ ^ *pb++);
  return neq == 0U;
}
