import qbs

DynamicLibrary {
    name: "tee"
    Depends { name: "cpp" }
    cpp.includePaths: ["include"]
    cpp.dynamicLibraries: ["uuid", "rt", "crypt", "z"]

    destinationDirectory: '.'

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: "include"
    }

    files: ["include/tee_client_api.h", "include/tee_emu_client_api.h",
        "include/tee_shared_data_types.h", 'src/tee_client_api_emu_ipc.c',
        'src/utils.h', 'src/utils.c', "include/com_protocol.h", "src/com_protocol.c",
        "include/socket_help.h", "src/socket_help.c"
    ]
}
