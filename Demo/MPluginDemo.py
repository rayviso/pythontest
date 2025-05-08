import json
import subprocess
from functools import partial

subprocess.Popen = partial(subprocess.Popen, encoding="utf-8")
import execjs


def js_test():
    # mTokenBasicOper.js
    with open("../UkeyJS/base64.js", "r", encoding="utf-8-sig") as f1, open("../UkeyJS/mToken.js", "r", encoding="utf-8-sig") as f2, open("../UkeyJS/mTokenBasicOper.js", "r", encoding="utf-8-sig") as f3, open("../UkeyJS/test.js", "r", encoding="utf-8-sig") as f4:
        js = f1.read() + "\n" + f2.read() + "\n" + f3.read() + "\n" + f4.read()


    js = execjs.compile(js)
    r1 = js.call("btnFindKey")
    print(r1)


if __name__ == "__main__":
    js_test()
