list (APPEND everest_src)
list (APPEND everest_inc)
list (APPEND everest_def)

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
execute_process(COMMAND ${PERL_EXECUTABLE} ${ROOT}/scripts/config.pl -f ${ROOT}/include/mbedtls/config.h get MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED RESULT_VARIABLE result)

if(${result} EQUAL 0)
  set(everest_src
    ${CMAKE_CURRENT_SOURCE_DIR}/library/everest.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/x25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/kremlib/FStar_UInt_8_16_32_64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/kremlib/fstar_uint128.c
  )

  if (${CMAKE_LIBRARY_ARCHITECTURE} STREQUAL "x86_64-linux-gnu")
  list(APPEND everest_src
    ${CMAKE_CURRENT_SOURCE_DIR}/library/Hacl_Curve25519.c)
  else()
  list(APPEND everest_def -DKRML_VERIFIED_UINT128)
  list(APPEND everest_src
    ${CMAKE_CURRENT_SOURCE_DIR}/library/legacy/Hacl_Curve25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/kremlib/FStar_UInt128_extracted.c
  )
  endif()

  list(APPEND everest_inc ${ROOT}/include ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include/everest ${CMAKE_CURRENT_SOURCE_DIR}/include/everest/kremlib)

  execute_process(COMMAND ${PERL_EXECUTABLE} ${ROOT}/scripts/config.pl -f ${ROOT}/include/mbedtls/config.h get MBEDTLS_ECDH_VARIANT_EVEREST_AES_GCM RESULT_VARIABLE result)
  if(${result} EQUAL 0)
    if(CMAKE_COMPILER_IS_MSVC)
      list(APPEND everest_src ${CMAKE_CURRENT_SOURCE_DIR}/library/aesgcm.asm)
    elseif(WIN32)
      list(APPEND everest_src ${CMAKE_CURRENT_SOURCE_DIR}/library/aesgcm-gcc.S)
    elseif(APPLE)
      list(APPEND everest_src ${CMAKE_CURRENT_SOURCE_DIR}/library/aesgcm-osx.S)
    elseif (${CMAKE_LIBRARY_ARCHITECTURE} STREQUAL "x86_64-linux-gnu")
      list(APPEND everest_src ${CMAKE_CURRENT_SOURCE_DIR}/library/aesgcm-linux.S)
    else(CMAKE_COMPILER_IS_MSVC)
      # Nothing.
    endif(CMAKE_COMPILER_IS_MSVC)
  endif()

  execute_process(COMMAND ${PERL_EXECUTABLE} ${ROOT}/scripts/config.pl -f ${ROOT}/include/mbedtls/config.h get MBEDTLS_EDDSA_C RESULT_VARIABLE result)
  if(${result} EQUAL 0)
    if (${CMAKE_LIBRARY_ARCHITECTURE} STREQUAL "x86_64-linux-gnu")
      list(APPEND everest_src ${CMAKE_CURRENT_SOURCE_DIR}/library/Hacl_Ed25519.c)
    else()
      list(APPEND everest_src ${CMAKE_CURRENT_SOURCE_DIR}/library/legacy/Hacl_Ed25519.c)
    endif()
  endif()

  if(INSTALL_MBEDTLS_HEADERS)

      file(GLOB_RECURSE headers "${CMAKE_CURRENT_SOURCE_DIR}/include/everest/*.h")

      install(FILES ${headers}
          DESTINATION include/everest
          PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

  endif(INSTALL_MBEDTLS_HEADERS)

endif()

set(thirdparty_src ${thirdparty_src} ${everest_src} PARENT_SCOPE)
set(thirdparty_inc ${thirdparty_inc} ${everest_inc} PARENT_SCOPE)
set(thirdparty_def ${thirdparty_def} ${everest_def} PARENT_SCOPE)
