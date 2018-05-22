/* Custom inttypes.h for VS2010
   KreMLin requires these definitions,
   but VS2010 doesn't provide them. */

#ifndef _INTTYPES_H_VS2010
#define _INTTYPES_H_VS2010

#include <stdint.h>

#ifdef _MSC_VER
#define inline __inline
#endif

/* VS2010 unsigned long == 8 bytes */

#define PRIx64 "%xl"


#endif
