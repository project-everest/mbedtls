execute_process(COMMAND ${PERL_EXECUTABLE} ../../scripts/config.pl -f ../../include/mbedtls/config.h get MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED RESULT_VARIABLE result)

if(${result} EQUAL 0)
  set(src_everest
    ${CMAKE_CURRENT_SOURCE_DIR}/library/everest.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/x25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/kremlib/FStar_UInt_8_16_32_64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/kremlib/fstar_uint128.c
  )

  if (${CMAKE_LIBRARY_ARCHITECTURE} STREQUAL "x86_64-linux-gnu")
  list(APPEND src_everest ${CMAKE_CURRENT_SOURCE_DIR}/library/Hacl_Curve25519.c)
  else()
  add_definitions(-DKRML_VERIFIED_UINT128)
  list(APPEND src_everest
    ${CMAKE_CURRENT_SOURCE_DIR}/library/legacy/Hacl_Curve25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/kremlib/FStar_UInt128_extracted.c
  )
  endif()

  execute_process(COMMAND ${PERL_EXECUTABLE} ../../scripts/config.pl -f ../../include/mbedtls/config.h get MBEDTLS_ECDH_VARIANT_EVEREST_AES_GCM RESULT_VARIABLE result)
  if(${result} EQUAL 0)
    enable_language(ASM)
    if(CMAKE_COMPILER_IS_MSVC)
      list(APPEND src_everest ${CMAKE_CURRENT_SOURCE_DIR}/library/aesgcm.asm)
    elseif(WIN32)
      list(APPEND src_everest ${CMAKE_CURRENT_SOURCE_DIR}/library/aesgcm-gcc.S)
    elseif(APPLE)
      list(APPEND src_everest ${CMAKE_CURRENT_SOURCE_DIR}/library/aesgcm-osx.S)
    else(CMAKE_COMPILER_IS_MSVC)
      list(APPEND src_everest ${CMAKE_CURRENT_SOURCE_DIR}/library/aesgcm-linux.S)
    endif(CMAKE_COMPILER_IS_MSVC)
  endif()

  execute_process(COMMAND ${PERL_EXECUTABLE} ../../scripts/config.pl -f ../../include/mbedtls/config.h get MBEDTLS_EDDSA_C RESULT_VARIABLE result)
  if(${result} EQUAL 0)
  list(APPEND src_everest ${CMAKE_CURRENT_SOURCE_DIR}/library/Hacl_Ed25519.c)
  endif()

  add_library(everest STATIC ${src_everest})
  set_target_properties(everest PROPERTIES INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/../../include;${CMAKE_CURRENT_SOURCE_DIR}/include;${CMAKE_CURRENT_SOURCE_DIR}/include/everest;${CMAKE_CURRENT_SOURCE_DIR}/include/everest/kremlib")

  if(INSTALL_MBEDTLS_HEADERS)

      file(GLOB_RECURSE headers "${CMAKE_CURRENT_SOURCE_DIR}/include/everest/*.h")

      install(FILES ${headers}
          DESTINATION include/everest
          PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

  endif(INSTALL_MBEDTLS_HEADERS)
endif()

get_target_property(everest_includes everest INCLUDE_DIRECTORIES)
list(APPEND thirdparty_libs everest)
list(APPEND thirdparty_includes ${everest_includes})
set(thirdparty_libs ${thirdparty_libs} PARENT_SCOPE)
set(thirdparty_includes ${thirdparty_includes} PARENT_SCOPE)