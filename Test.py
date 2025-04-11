from warnings import catch_warnings

from Common.Base import *
from Common.Sm import *
from gmssl import *

# print("hello python")
# print(MyConverter.string_to_base64("hello python"))
# print(MySm.sm3_digest_hex("hello python"))
# print(MySm.sm3_hmac_digest_with_key_base64("hello python", MySm.random_bytes16()))



sm2 = Sm2Key()
sm2.generate_key()
publickey = Sm2Key()


try:
    publickey.import_public_key_info_pem('d:/public.pem')
    publickey.
except IOError:
    raise IOError