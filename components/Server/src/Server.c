/*
 * Server
 *
 * Copyright (C) 2022-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#include <camkes.h>
#include <camkes/dataport.h>
#include <stdio.h>
#include <string.h>

#include "lib_debug/Debug.h"

#include "OS_FileSystem.h"
#include "OS_Crypto.h"


// Configuration of Crypto API in "LIBRARY" mode; assign entropy source
// as defined in CAmkES.
static const OS_Crypto_Config_t cryptoCfg =
{
    .mode = OS_Crypto_MODE_LIBRARY,
    .entropy = IF_OS_ENTROPY_ASSIGN(
        entropy_rpc,
        entropy_dp),
};

//------------------------------------------------------------------------------
static OS_FileSystem_Config_t fatCfg =
{
    .type = OS_FileSystem_Type_FATFS,
    .size = OS_FileSystem_USE_STORAGE_MAX,
    .storage = IF_OS_STORAGE_ASSIGN(
        storage_rpc,
        storage_dp),
};

//------------------------------------------------------------------------------
static void
test_OS_FileSystem(OS_FileSystem_Config_t* cfg, uint8_t * fileData, off_t fileSize) {
    OS_Error_t ret;
    OS_FileSystem_Handle_t hFs;

    const char* fileName = "hello.txt";
    OS_FileSystemFile_Handle_t hFile;

    // Init file system
    if ((ret = OS_FileSystem_init(&hFs, cfg)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystem_init() failed, code %d", ret);
    }

    // Format file system
    if ((ret = OS_FileSystem_format(hFs)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystem_format() failed, code %d", ret);
    }

    // Mount file system
    if ((ret = OS_FileSystem_mount(hFs)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystem_mount() failed, code %d", ret);
    }

    // Open file
    if((ret = OS_FileSystemFile_open(hFs, &hFile, fileName,
                                OS_FileSystem_OpenMode_RDWR,
                                OS_FileSystem_OpenFlags_CREATE)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_open() failed, code %d", ret);
    }

    printf("Server: Storing String on storage backend.\n");

    // Write to the file
    off_t to_write, written;
    to_write = fileSize;
    written = 0;

    while (to_write > 0)
    {
        if((ret = OS_FileSystemFile_write(hFs, hFile, written, fileSize, fileData)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_FileSystemFile_write() failed, code %d", ret);
        }

        written  += fileSize;
        to_write -= fileSize;
    }

    printf("Server: Loading String from storage backend.\n");

    // Read from the file
    uint8_t buf[fileSize];
    off_t to_read, read;
    to_read = fileSize;
    read = 0;

    while (to_read > 0)
    {
        if((ret = OS_FileSystemFile_read(hFs, hFile, read, sizeof(buf), buf)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_FileSystemFile_read() failed, code %d", ret);
        }

        if(memcmp(fileData, buf, sizeof(buf)))
            Debug_LOG_ERROR("File content read does not equal file content to be written.");

        read    += sizeof(buf);
        to_read -= sizeof(buf);
    }

    // Close file
    if((ret = OS_FileSystemFile_close(hFs, hFile)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_close() failed, code %d", ret);
    }

    // Clean up
    if((ret = OS_FileSystem_unmount(hFs)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystem_unmount() failed, code %d", ret);
    }

    if ((ret = OS_FileSystem_free(hFs)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystem_free() failed, code %d", ret);
    }
}

void reverse(char s[]) {
    int length = strlen(s);
    int temp, i, j;
    for(i = 0, j = length - 1; i < j; i++, j--) {
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
}

void if_server_reverse(dataport_ptr_t *ptr) {
    char *olleh;

    olleh = (char *) dataport_unwrap_ptr(*ptr);

    printf("Server: Receiving String '%s' from Client.\n", olleh);
    printf("Server: Reversing String.\n");

    reverse(olleh);

    printf("Server: Initializing Crypto API.\n");

    // Definition of a key-generation spec for a 128-bit AES key
    static OS_CryptoKey_Spec_t aes128Spec = {
        .type = OS_CryptoKey_SPECTYPE_BITS,
        .key = {
            .type = OS_CryptoKey_TYPE_AES,
            .params.bits = 128
        }
    };

    // Declare handles for API and objects
    OS_Crypto_Handle_t hCrypto;
    OS_CryptoKey_Handle_t hKey;
    OS_CryptoCipher_Handle_t hCipher;

    // Declare inputs and outputs for crypto operation
    size_t length = strlen(olleh);
    uint8_t input[length];
    uint8_t output[length];
    memcpy(input, olleh, length);

    OS_Crypto_init(&hCrypto, &cryptoCfg);

    // Generate a new AES key based on the spec provided above
    OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec);

    // Create a cipher object to encrypt data with AES in ECB (does not require an IV!)
    OS_CryptoCipher_init(&hCipher,
                        hCrypto,
                        hKey,
                        OS_CryptoCipher_ALG_AES_ECB_ENC,
                        NULL,
                        0);

    printf("Server: Encrypting String.\n");

    OS_CryptoCipher_process(hCipher, input, length, output, &length);

    memset(input, 0, length);

    // Storing/Loading String to/from storage backend
    test_OS_FileSystem(&fatCfg, output, length);

    printf("Server: Decrypting String.\n");

    // Create a cipher object to decrypt data with AES in ECB (does not require an IV!)
    OS_CryptoCipher_init(&hCipher,
                        hCrypto,
                        hKey,
                        OS_CryptoCipher_ALG_AES_ECB_DEC,
                        NULL,
                        0);

    // Decrypt loaded String
    OS_CryptoCipher_process(hCipher, output, length, input, &length);

    memcpy(olleh, input, length);

    // Free everything
    OS_CryptoCipher_free(hCipher);
    OS_CryptoKey_free(hKey);
    OS_Crypto_free(hCrypto);

    strcpy((char *)buf_server, olleh);
    *ptr = dataport_wrap_ptr((void *)buf_server);
}