set(src_everest
  ${CMAKE_CURRENT_SOURCE_DIR}/library/everest.c
  ${CMAKE_CURRENT_SOURCE_DIR}/library/x25519.c
  ${CMAKE_CURRENT_SOURCE_DIR}/library/kremlib/FStar_UInt64_FStar_UInt32_FStar_UInt16_FStar_UInt8.c
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

add_library(everest STATIC ${src_everest})
set_target_properties(everest PROPERTIES INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/../../include;${CMAKE_CURRENT_SOURCE_DIR}/include;${CMAKE_CURRENT_SOURCE_DIR}/include/everest;${CMAKE_CURRENT_SOURCE_DIR}/include/everest/kremlib")


if(INSTALL_MBEDTLS_HEADERS)

    file(GLOB_RECURSE headers "${CMAKE_CURRENT_SOURCE_DIR}/include/everest/*.h")

    install(FILES ${headers}
        DESTINATION include/everest
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

endif(INSTALL_MBEDTLS_HEADERS)
