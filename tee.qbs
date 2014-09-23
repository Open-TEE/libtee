import qbs

DynamicLibrary {
    name: "tee"
    Depends { name: "cpp" }
    Depends { name: "CommonApi" }
    cpp.includePaths: ["include"]
    cpp.dynamicLibraries: ["uuid", "rt", "crypt"]
    cpp.warningLevel: "none"

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: "include"
    }

    files: ["include/tee_client_api.h", "include/tee_emu_client_api.h",
        'src/open_emu_ipc/tee_client_api_emu_ipc.c',
        'src/open_emu_ipc/utils.h', 'src/open_emu_ipc/utils.c',
        "../emulator/include/com_protocol.h", "../emulator/include/general_data_types.h",
        "../emulator/include/socket_help.h"
    ]
}
