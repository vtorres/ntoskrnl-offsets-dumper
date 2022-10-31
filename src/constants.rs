pub const RADARE_EXECUTABLE_NAME: &str = r"radare2";

pub const NTOSKRNL_DEFAULT_EXECUTABLE_FILE: &str = r"C:/Windows/System32/ntoskrnl.exe";

pub const SEMANTIC_VERSIONING_REGEX: &str =
    r"(0|(?:[1-9]\d*))(?:\.(0|(?:[1-9]\d*))(?:\.(0|(?:[1-9]\d*)))?(?:\-([\w][\w\.\-_]*))?)?";

pub const OFFSETS_REGEX: &str = r"0x[a-f0-9]+";

pub type StructWithCondition = [&'static str; 2];

pub const EXPECTED_SYMBOLS: [StructWithCondition; 14] = [
    ["_LIST_ENTRY ActiveProcessLinks", ""],
    ["void * UniqueProcessId", ""],
    ["_LIST_ENTRY ThreadListHead", "struct _EPROCESS"],
    ["_PS_PROTECTION Protection", ""],
    ["_EX_FAST_REF Token", ""],
    ["_HANDLE_TABLE* ObjectTable", ""],
    ["_KTRAP_FRAME* TrapFrame", "struct _KTHREAD"],
    ["uint64_t Rip", "struct _KTRAP_FRAME"],
    ["_LIST_ENTRY ThreadListEntry", "struct _ETHREAD"],
    ["_CLIENT_ID Cid", ""],
    ["EtwThreatIntProvRegHandle", ""],
    ["_ETW_GUID_ENTRY* GuidEntry", ""],
    ["_TRACE_ENABLE_INFO ProviderEnableInfo", ""],
    ["_GUID Guid", "struct _ETW_GUID_ENTRY"],
];

pub const EXPECTED_FILE_VERSION_INFO: &str = "FileVersion:";

pub const EXPECTED_RADARE_MAJOR_VERSION: i8 = 5;