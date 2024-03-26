/*
 * Client
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

int run(void) {
    char *hello = "hello_sel4_user!";

    printf("Client: Sending String '%s' to Server.\n", hello);

    strcpy((char *)buf_client, hello);
    dataport_ptr_t ptr = dataport_wrap_ptr((void *)buf_client);
    if_client_reverse(&ptr);
    hello = dataport_unwrap_ptr(ptr);

    printf("Client: Receiving reversed String '%s' from Server.\n", hello);

    return 0;
}