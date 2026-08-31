cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME "scomm_smime")
project(${PROJECT_NAME} LANGUAGES CXX)

get_filename_component(_SCOMM_SMIME_LINUX_DIR "${CMAKE_CURRENT_SOURCE_DIR}" REALPATH)
get_filename_component(SCOMM_SMIME_ROOT "${_SCOMM_SMIME_LINUX_DIR}/../../.." ABSOLUTE)
set(SCOMM_SMIME_SO "${SCOMM_SMIME_ROOT}/target/release/libscomm_smime.so")

add_custom_command(
  OUTPUT "${SCOMM_SMIME_SO}"
  COMMAND cargo build --release -p scomm-smime-ffi
  WORKING_DIRECTORY "${SCOMM_SMIME_ROOT}"
  COMMENT "Building libscomm_smime.so"
  VERBATIM
)
add_custom_target(scomm_smime_rust ALL DEPENDS "${SCOMM_SMIME_SO}")

set(scomm_smime_bundled_libraries
  "${SCOMM_SMIME_SO}"
  PARENT_SCOPE
)
