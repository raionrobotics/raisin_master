"""
Constants used throughout RAISIN.
"""

# ROS message type mapping to C++ types
TYPE_MAPPING = {
    "bool": "bool",
    "byte": "uint8_t",
    "char": "uint8_t",
    "float32": "float",
    "float64": "double",
    "int8": "int8_t",
    "uint8": "uint8_t",
    "int16": "int16_t",
    "uint16": "uint16_t",
    "int32": "int32_t",
    "uint32": "uint32_t",
    "int64": "int64_t",
    "uint64": "uint64_t",
    "string": "std::string",
    "wstring": "std::u16string",
}

STRING_TYPES = ["std::string", "std::u16string"]

SYMLINK_CONFIG_HELP = (
    "Symlink each package's config/ into install/ (default) so source edits apply without "
    "rebuilding; --copy-config copies instead."
)


class Colors:
    """ANSI color codes for terminal output."""

    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    RED = "\033[91m"
    RESET = "\033[0m"
