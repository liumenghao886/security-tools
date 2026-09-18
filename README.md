# Security Tools

我在学习网络安全过程中编写的工具集，用于 CTF 靶场和授权测试环境。

> ⚠️ **免责声明**：所有工具仅限本地环境、CTF 靶场或已获得书面授权的测试目标使用。
> 未经授权对他人系统进行测试属于违法行为。

## 工具列表

| 工具 | 说明 | 技术点 |
|---|---|---|
| [blind_sqli.py](blind_sqli.py) | 布尔盲注自动化脚本 | 二分法、requests、ASCII 编码转换 |

## 环境要求

- Python 3.8+
- 安装依赖：`pip install requests`

## 使用方法

```bash
python blind_sqli.py
```

运行前请修改脚本开头的**配置区**（靶场地址、payload 格式、判断关键词）。
