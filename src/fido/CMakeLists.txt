idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS .
    PRIV_INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/../../pico-keys-sdk/src/compat
    REQUIRES esp_tinyusb mbedtls efuse pico-keys-sdk app_update
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
