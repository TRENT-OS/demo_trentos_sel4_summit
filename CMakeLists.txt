#
# Demo seL4 Summit
#
# Copyright (C) 2022, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

#-------------------------------------------------------------------------------
os_set_config_file(
    "system_config.h"
    CONFIG_PROJECT_NAME "system_config"
)

#-------------------------------------------------------------------------------
project(demo_sel4_summit C)

RamDisk_DeclareCAmkESComponent(
    RamDisk
)

EntropySource_DeclareCAmkESComponent(
    EntropySource
)

DeclareCAmkESComponent(
    Client
    SOURCES
        components/Client/src/Client.c
)

DeclareCAmkESComponent(
    Server
    SOURCES
        components/Server/src/Server.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        system_config
        lib_debug
        os_core_api
        os_filesystem
        os_crypto
)

DeclareAndCreateCamkESSystem(demo_sel4_summit.camkes)
GenerateSimulateScript()