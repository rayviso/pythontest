import base64
# from pyasn1_modules import
# from pyasn1.codec.der import decoder, encoder

class MyASN1(object):
    def __init__(self):
        pass

    # @staticmethod
    # def

class MyConverter(object):

    def __init__(self):
        pass

    # string -> bytes @utf-8
    @staticmethod
    def string_to_bytes_utf8(string):
        return string.encode("utf-8")

    # string -> bytes @ascii
    @staticmethod
    def string_to_bytes_ascii(string):
        return string.encode("ascii")

    # string -> bytes @gbk
    @staticmethod
    def string_to_bytes_gbk(string):
        return string.encode("gbk")

    # string -> base64
    @staticmethod
    def string_to_base64(string):
        return base64.b64encode(string.encode()).decode()

    # string -> hex
    @staticmethod
    def string_to_hex(string):
        return string.encode().hex()

    # string -> hex
    @staticmethod
    def string_to_hex_with_space(string):
        return ' '.join(f"{b:02x}" for b in string.encode())

    # bytes -> string
    @staticmethod
    def bytes_to_string_windows1252(bytes):
        return bytes.decode("windows-1252")

    # bytes -> string
    @staticmethod
    def bytes_to_string_latin1(bytes):
        return bytes.decode("latin-1")

    # bytes -> string
    @staticmethod
    def bytes_to_string_utf8(bytes):
        return bytes.decode("utf8")

    # bytes -> string
    @staticmethod
    def bytes_to_string_gbk(bytes):
        return bytes.decode("gbk")

    # bytes -> string
    @staticmethod
    def bytes_to_string_ascii(bytes):
        return bytes.decode("ascii")

    # bytes -> base64
    @staticmethod
    def bytes_to_base64(bytes):
        return base64.b64encode(bytes).decode()

    # bytes -> hex
    @staticmethod
    def bytes_to_hex(bytes):
        return bytes.hex()

    # bytes -> hex
    @staticmethod
    def bytes_to_hex_with_space(bytes):
        return ' '.join(f"{b:02x}" for b in bytes)

    # base64 -> hex
    @staticmethod
    def base64_to_hex(b64):
        try:
            return base64.b64decode(b64).hex()
        except ValueError:
            raise ValueError("Invalid Value")

    # base64 -> bytes
    @staticmethod
    def base64_to_bytes(b64):
        try:
            return base64.b64decode(b64)
        except ValueError:
            raise ValueError("Invalid Value")

    # base64 -> string
    @staticmethod
    def base64_to_string(b64):
        try:
            return base64.b64decode(b64).decode("utf-8")
        except ValueError:
            raise ValueError("Invalid Value")

    # hex -> base64
    @staticmethod
    def hex_to_base64(hex):
        try:
            return base64.b64encode(bytes.fromhex(hex))
        except ValueError:
            raise ValueError("Invalid Value")

    # hex -> bytes
    @staticmethod
    def hex_string_to_bytes(hex):
        try:
            return bytes.fromhex(hex)
        except ValueError:
            raise ValueError("Invalid Value")

    # hex -> string
    @staticmethod
    def hex_to_string(hex):
        try:
            return base64.b64encode(bytes.fromhex(hex)).decode("utf-8")
        except ValueError:
            raise ValueError("Invalid Value")


    # bit -> hex 2进制转16进制
    @staticmethod
    def bit_to_hex(bit_str):
        padding = (4 - len(bit_str) % 4) % 4
        bit_str_padded = '0' * padding + bit_str
        # 转换为hex字符串
        hex_str = ''.join([format(int(bit_str_padded[i:i + 4], 2), 'x') for i in range(0, len(bit_str_padded), 4)])
        return hex_str