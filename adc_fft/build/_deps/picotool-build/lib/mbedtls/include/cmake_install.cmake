# Install script for directory: /pico-sdk/lib/mbedtls/include

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/work/awulff-pico-playground/adc_fft/build/_deps")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/mbedtls" TYPE FILE MESSAGE_NEVER PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/pico-sdk/lib/mbedtls/include/mbedtls/aes.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/aesni.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/arc4.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/aria.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/asn1.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/asn1write.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/base64.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/bignum.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/blowfish.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/bn_mul.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/camellia.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ccm.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/certs.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/chacha20.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/chachapoly.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/check_config.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/cipher.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/cipher_internal.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/cmac.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/compat-1.3.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/config.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/config_psa.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/constant_time.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ctr_drbg.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/debug.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/des.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/dhm.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ecdh.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ecdsa.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ecjpake.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ecp.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ecp_internal.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/entropy.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/entropy_poll.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/error.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/gcm.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/havege.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/hkdf.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/hmac_drbg.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/md.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/md2.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/md4.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/md5.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/md_internal.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/memory_buffer_alloc.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/net.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/net_sockets.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/nist_kw.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/oid.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/padlock.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/pem.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/pk.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/pk_internal.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/pkcs11.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/pkcs12.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/pkcs5.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/platform.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/platform_time.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/platform_util.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/poly1305.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/psa_util.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ripemd160.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/rsa.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/rsa_internal.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/sha1.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/sha256.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/sha512.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ssl.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ssl_cache.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ssl_ciphersuites.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ssl_cookie.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ssl_internal.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/ssl_ticket.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/threading.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/timing.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/version.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/x509.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/x509_crl.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/x509_crt.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/x509_csr.h"
    "/pico-sdk/lib/mbedtls/include/mbedtls/xtea.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/psa" TYPE FILE MESSAGE_NEVER PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/pico-sdk/lib/mbedtls/include/psa/crypto.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_builtin_composites.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_builtin_primitives.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_compat.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_config.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_driver_common.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_driver_contexts_composites.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_driver_contexts_primitives.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_extra.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_platform.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_se_driver.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_sizes.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_struct.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_types.h"
    "/pico-sdk/lib/mbedtls/include/psa/crypto_values.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/work/awulff-pico-playground/adc_fft/build/_deps/picotool-build/lib/mbedtls/include/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
