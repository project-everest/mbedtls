THIRDPARTY_INCLUDES+=-I../3rdparty/everest/include -I../3rdparty/everest/include/everest -I../3rdparty/everest/include/everest/kremlib

THIRDPARTY_CRYPTO_OBJECTS+= \
	../3rdparty/everest/library/everest.o \
	../3rdparty/everest/library/x25519.o \
	../3rdparty/everest/library/Hacl_Curve25519_joined.o \
	../3rdparty/everest/library/Hacl_Ed25519.o \
	../3rdparty/everest/library/kremlib/FStar_UInt64_FStar_UInt32_FStar_UInt16_FStar_UInt8.o \
	../3rdparty/everest/library/kremlib/fstar_uint128.o
