set(thirdparty_libs "")
set(thirdparty_includes "")

add_subdirectory(everest)

set(thirdparty_libs ${thirdparty_libs} PARENT_SCOPE)
set(thirdparty_includes ${thirdparty_includes} PARENT_SCOPE)
