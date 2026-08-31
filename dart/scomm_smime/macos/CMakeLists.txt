cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME "scomm_smime")
project(${PROJECT_NAME} LANGUAGES CXX)

get_filename_component(_SCOMM_SMIME_MACOS_DIR "${CMAKE_CURRENT_SOURCE_DIR}" REALPATH)
get_filename_component(SCOMM_SMIME_ROOT "${_SCOMM_SMIME_MACOS_DIR}/../../.." ABSOLUTE)
set(SCOMM_SMIME_DYLIB "${SCOMM_SMIME_ROOT}/target/release/libscomm_smime.dylib")

add_custom_command(
  OUTPUT "${SCOMM_SMIME_DYLIB}"
  COMMAND cargo build --release -p scomm-smime-ffi
  WORKING_DIRECTORY "${SCOMM_SMIME_ROOT}"
  COMMENT "Building libscomm_smime.dylib"
  VERBATIM
)
add_custom_target(scomm_smime_rust ALL DEPENDS "${SCOMM_SMIME_DYLIB}")

set(scomm_smime_bundled_libraries
  "${SCOMM_SMIME_DYLIB}"
  PARENT_SCOPE
)
