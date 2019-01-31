set(thirdparty_libs "")
set(thirdparty_includes "")

execute_process(COMMAND ${PERL_EXECUTABLE} ../scripts/config.pl -f ../include/mbedtls/config.h get MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED RESULT_VARIABLE result)

if(${result} EQUAL 0)
  add_subdirectory(everest)
  get_target_property(everest_includes everest INCLUDE_DIRECTORIES)
  list(APPEND thirdparty_libs everest)
  list(APPEND thirdparty_includes ${everest_includes})
endif()

set(thirdparty_libs ${thirdparty_libs} PARENT_SCOPE)
set(thirdparty_includes ${thirdparty_includes} PARENT_SCOPE)
