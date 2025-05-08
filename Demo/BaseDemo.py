from Common.Base import *


def test():

    msg = ("Hello 我是中国人")

    print(msg.encode("utf-8"))
    print(msg.encode("unicode_escape"))
    print(msg.encode("gbk"))

    rst = ""
    for b in msg.encode("utf-8"):
        rst += " 0x".join(str(b))
    rst = "0x" + rst
    print(rst)

    rst = ""
    for b in msg.encode("unicode_escape"):
        rst += " 0x".join(str(b))
    rst = "0x" + rst
    print(rst)

    rst = ""
    for b in msg.encode("gbk"):
        rst += " 0x".join(str(b))
    rst = "0x" + rst
    print(rst)


    print(MyConverter.bytes_to_base64(msg.encode("utf-8")))
    print(MyConverter.bytes_to_base64(msg.encode("unicode_escape")))
    print(MyConverter.bytes_to_base64(msg.encode("gbk")))


if __name__ == '__main__':
    test()