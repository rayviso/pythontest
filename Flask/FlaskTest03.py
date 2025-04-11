#!/usr/bin/python3
import redis
from flask import Flask
# import sys
# import time

app = Flask(__name__)
cache = redis.Redis(host="127.0.0.1", port="31005")


def get_count():
    return cache.incrby("tommy", 1)
    # return cache.incr("hits")
    pass


@app.route("/")
def index():
    cnt = get_count()
    return "<h1>hello flask, cnt={}".format(cnt)
    pass

def main():
    print("hello python")
    app.run(host="0.0.0.0", port=8801)

if __name__ == "__main__":
    main()