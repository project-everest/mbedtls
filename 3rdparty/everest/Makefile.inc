EVEREST_ENABLED=$(shell perl ../scripts/config.pl -f ../include/mbedtls/config.h get MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED; echo $$?)
EVEREST_AESGCM_ENABLED=$(shell perl ../scripts/config.pl -f ../include/mbedtls/config.h get MBEDTLS_ECDH_VARIANT_EVEREST_AES_GCM; echo $$?)
EDDSA_ENABLED=$(shell perl ../scripts/config.pl -f ../include/mbedtls/config.h get MBEDTLS_EDDSA_C; echo $$?)

ifeq ($(EVEREST_ENABLED),0)
THIRDPARTY_INCLUDES+=-I../3rdparty/everest/include -I../3rdparty/everest/include/everest -I../3rdparty/everest/include/everest/kremlib

THIRDPARTY_OBJECTS+= \
	../3rdparty/everest/library/everest.o \
	../3rdparty/everest/library/x25519.o \
	../3rdparty/everest/library/kremlib/FStar_UInt_8_16_32_64.o \
	../3rdparty/everest/library/kremlib/fstar_uint128.o

ifeq ($(shell getconf LONG_BIT),64)
THIRDPARTY_OBJECTS+=\
	../3rdparty/everest/library/Hacl_Curve25519.o
else
CFLAGS+="-DKRML_VERIFIED_UINT128"
THIRDPARTY_OBJECTS+=\
	../3rdparty/everest/library/legacy/Hacl_Curve25519.o \
	../3rdparty/everest/library/kremlib/FStar_UInt128_extracted.o
endif
endif

ifeq ($(EVEREST_AESGCM_ENABLED),0)
THIRDPARTY_OBJECTS+= \
	../3rdparty/everest/library/aesgcm-linux.o
endif

ifeq ($(EDDSA_ENABLED),0)
THIRDPARTY_OBJECTS+= \
	../3rdparty/everest/library/Hacl_Ed25519.o
endif
