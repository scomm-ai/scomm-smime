cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME "scomm_smime")
project(${PROJECT_NAME} LANGUAGES CXX)

get_filename_component(_SCOMM_SMIME_WINDOWS_DIR "${CMAKE_CURRENT_SOURCE_DIR}" REALPATH)
get_filename_component(SCOMM_SMIME_ROOT "${_SCOMM_SMIME_WINDOWS_DIR}/../../.." ABSOLUTE)
set(SCOMM_SMIME_DLL "${SCOMM_SMIME_ROOT}/target/release/scomm_smime.dll")

add_custom_command(
  OUTPUT "${SCOMM_SMIME_DLL}"
  COMMAND cargo build --release -p scomm-smime-ffi
  WORKING_DIRECTORY "${SCOMM_SMIME_ROOT}"
  COMMENT "Building scomm_smime.dll"
  VERBATIM
)
add_custom_target(scomm_smime_rust ALL DEPENDS "${SCOMM_SMIME_DLL}")

set(scomm_smime_bundled_libraries
  "${SCOMM_SMIME_DLL}"
  PARENT_SCOPE
)
