#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import redis
from flask import Flask

app=Flask(__name__)

@app.route('/')
def index():
    return '<h1>Hello Index</h1>'

def main():
    print('hello python by pycharm')
    pass

if __name__ == '__main__':
    main()
    app.run(host='0.0.0.0', port='8899', debug=False)