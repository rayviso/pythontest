import pyodbc                       # pip install pyodbc
from pyodbc import Connection
from typing import Any, Dict, List


class MyMssql(object):
    def __init__(self, server=None, database=None, user=None, password=None, connect_string=None):
        self.connection = None
        self.cursor = None
        self.server = server
        self.database = database
        self.user = user
        self.password = password
        if connect_string is not None:
            self.connect_string = connect_string
        else:
            self.connect_string = (
                'DRIVER={ODBC Driver 18 for SQL Server};'  # 18 为最新版本，要确定对应的ODBC驱动版本
                f'SERVER={self.server};'
                f'DATABASE={self.database};'
                f'UID={self.user};'
                f'PWD={self.password};'
                f'TrustServerCertificate=yes'  # 非信任证书也可以进行连接
            )

    def is_init_connection(self):
        if self.connection is None:
            self.open_connection()

    def open_connection(self):
        try:
            self.connection = pyodbc.connect(self.connect_string)
            self.cursor = self.connection.cursor()
        except Exception as e:
            print(f"连接失败：{e}")

    def close_connection(self):
        if self.connection.cursor is not None:
            self.cursor.close()
        if self.connection is not None:
            self.connection.close()

    # 执行一般查询语句，返回值为一个list
    def execute_select(self, query: str) -> Any | None:
        try:
            self.is_init_connection()
            self.cursor.execute(query)
            return self.cursor.fetchall()
        except pyodbc.DatabaseError as e:
            self.connection.rollback()  # 回滚事务
            print(f"查询失败: {e}")

    # 执行Count查询语句，返回值是表的行数
    def execute_select_count(self, query: str) -> Any | None:
        try:
            self.is_init_connection()
            self.cursor.execute(query)
            return self.cursor.fetchone()[0]
        except pyodbc.DatabaseError as e:
            self.connection.rollback()  # 回滚事务
            print(f"查询失败: {e}")

    # sql = """SELECT * FROM users_copy1 ORDER BY indexnumber OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;"""
    def execute_select_by_pages_general(self, query: str, page: int, page_size: int)  -> Any | None:
        try:
            self.is_init_connection()
            # 参数校验
            page = max(1, page)
            page_size = max(1, min(page_size, 10000))  # 限制每页最多10000条

            # 计算偏移量
            offset = (page - 1) * page_size
            self.cursor.execute(query, offset, page_size)
            return self.cursor.fetchall()
        except pyodbc.DatabaseError as e:
            self.connection.rollback()  # 回滚事务
            print(f"查询失败: {e}")

    #     insert_query = """INSERT INTO users (id, name, gender, id_card_number, phone_number, address, ukey_id, password, passwordhash)
    #     	VALUES (NEWID(), ?, ?, ?, ?, ?, ?, ?, ?);"""
    def execute_insert(self, query: str, params=None):
        self.is_init_connection()

        try:
            self.cursor.execute(query, params)
            self.cursor.commit()
        except pyodbc.DatabaseError as e:
            self.connection.rollback()  # 回滚事务
            print(f"插入失败: {e}")

    def execute_insert_many_fast(self, query: str, params=None):
        self.is_init_connection()

        try:
            self.cursor.fast_executemany = True
            self.cursor.executemany(query, params)
            self.connection.commit()
        except pyodbc.DatabaseError as e:
            self.connection.rollback()  # 回滚事务
            print(f"插入失败: {e}")

    def execute_update_many_fast(self, query: str, params=None):
        self.is_init_connection()

        try:
            # self.connection.autocommit = False
            self.cursor.fast_executemany = True
            # self.cursor.execute("BEGIN TRANSACTION;")
            self.cursor.executemany(query, params)
            self.connection.commit()
        except pyodbc.DatabaseError as e:
            self.connection.rollback()  # 回滚事务
            print(f"插入失败: {e}")
