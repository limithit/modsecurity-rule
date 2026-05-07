

# ModSecurity 规则集与常用操作符指南

本仓库包含一些常用的 ModSecurity 规则，旨在防御暴力破解、Log4j2 漏洞以及近年来的高危 CVE 漏洞。

> **测试环境:** `libmodsecurity.so.3.0.8` & `ModSecurity-nginx v1.0.3`

---

## 📚 目录

- [规则简介](#-规则简介)
- [常用操作符详解](#常用操作符详解)
- [变量与转换函数](#-变量与转换函数)
- [实战：如何使用变量](#-实战如何使用变量)
- [阶段说明](#阶段说明)
- [规则示例](#规则示例)

---

## 📝 规则简介

ModSecurity 是一个开源 Web 应用程序防火墙（WAF），用于检测和防止 Web 应用程序攻击。它通过一组规则来匹配和处理请求与响应。

### 规则 ID 规范

虽然 ModSecurity 规则 ID 没有严格限制，但建议遵循以下约定以避免冲突：

- **范围建议:** 通常使用 **6 位数字**（100000 - 999999）。
- **OWASP CRS:** 使用 `900000` - `999999` 范围。
- **自定义规则:** 建议使用 `100000` - `199999` 范围。

### 执行顺序

规则的执行顺序**不由 ID 决定**，而是取决于：
1.  **阶段:** 规则所在的阶段（Phase 1-5）。
2.  **加载顺序:** 配置文件加载的顺序（文件名按字母顺序排序）。

---

##  常用操作符详解

下表详细解释了 ModSecurity 中常用的操作符及其用途。

| 操作符 | 描述与用法 |
| :--- | :--- |
| **`@pm`** | **部分匹配**匹配变量值是否包含列表中的任意字符串。例：`@pm bot spider crawler` |
| **`@pmFromFile`** | **文件列表匹配**匹配变量值是否包含文件中列出的任意字符串。文件每行一个字符串。例：`@pmFromFile bad-user-agents.txt` |
| **`@contains`** | **包含匹配**匹配变量值是否包含指定字符串（不支持正则）。例：`@contains admin` |
| **`@rx`** | **正则表达式**匹配变量值是否符合正则表达式。注意转义特殊字符。例：`@rx ^[a-z]+$` |
| **`@streq`** | **字符串全等**匹配变量值是否与给定字符串完全相等（区分大小写）。例：`@streq GET` |
| **`@eq`** | **数值/字符串相等**匹配变量值是否等于给定数字或列表中的项。例：`@eq 200` 或 `@eq GET POST` |
| **`@within`** | **列表包含**匹配变量值是否在给定列表中。例：`@within admin root` |
| **`@gt` / `@lt`** | **大于 / 小于**数值比较。例：`@gt 100` (大于100), `@lt 100` (小于100) |
| **`@ge`** | **大于等于**例：`@ge 100` |
| **`@beginsWith`** | **开头匹配**匹配变量值是否以指定字符串开头。例：`@beginsWith http` |
| **`@endsWith`** | **结尾匹配**匹配变量值是否以指定字符串结尾。例：`@endsWith .php` |
| **`@ipMatch`** | **IP 匹配**匹配 IP 地址或子网。不支持域名。例：`@ipMatch 192.168.0.1` 或 `@ipMatch 192.168.0.0/24` |
| **`@validateByteRange`** | **字节范围验证**验证变量是否只包含指定 ASCII 范围内的字节。例：`@validateByteRange 32-126` |
| **`@detectXSS`** | **XSS 检测**检测是否包含跨站脚本攻击向量（可能产生误报）。 |
| **`@detectSQLi`** | **SQL 注入检测**检测是否包含 SQL 注入攻击向量（可能产生误报）。 |
| **`@validateUrlEncoding`** | **URL 编码验证**验证是否符合有效的 URL 编码格式。 |

---

## 🔧 变量与转换函数

### 转换函数

- **`t:none`**: 取消所有转换函数。通常用于覆盖全局设置，确保原始数据被检查。
- **`t:lowercase`**: 将变量值转换为小写。用于防止大小写绕过（如 `Admin` 与 `admin`）。

### TX 变量 (事务变量)

`TX` 变量用于在规则执行过程中存储和访问数据。主要有两种创建方式：

#### 1. 使用 `capture` (自动创建)
配合 `@rx` 使用，自动将正则括号 `()` 捕获的内容存入 `TX:1`, `TX:2` 等。
- `TX:0`: 整个匹配字符串。
- `TX:1`: 第一个括号内的内容。

**示例:**
```apache
# 匹配 JWT 并捕获 Header 部分
SecRule ARGS "@rx ^([^.]+)\." "capture, ..."
# 后续规则可直接使用 TX:1
```

#### 2. 使用 `setvar` (手动创建)
更通用的方式，用于计数或存储特定数据。

**示例:**
```apache
# 统计 IP 请求次数
SecRule REMOTE_ADDR "^.*$" "id:100,phase:1,pass,nolog,setvar:ip.request_count=+1"

# 存储特定参数值
SecRule ARGS:user_id "@rx ^(\d+)$" "id:101,phase:2,pass,nolog,setvar:'tx.user_id=%{TX.1}'"
```

### 其他动作

- **`setvar`**: 设置变量值。
- **`expirevar`**: 设置变量过期时间。

---

## 🚀 实战：如何使用变量

定义了变量（如计数或提取值）后，需要通过后续规则来“消费”这些变量才能发挥作用。

### 1. 使用 `ip.request_count` 实现 IP 限流

单纯的计数规则只会增加数值，我们需要配合 `expirevar`（过期时间）和阈值判断规则来实现限流。

**核心逻辑：**
1.  **规则 A (计数):** 每次请求 `+1`，并设置 60 秒后自动清零。
2.  **规则 B (判断):** 检查变量值是否 `> 100`，如果是，则拒绝访问。

```apache
# --- 第一步：计数 ---
# 注意：必须加上 expirevar，否则计数器永远不会清零
SecRule REMOTE_ADDR "^.*$" \
    "id:100,\
    phase:1,\
    pass,\
    nolog,\
    setvar:ip.request_count=+1,\
    expirevar:ip.request_count=60"

# --- 第二步：使用变量进行拦截 ---
# 检查 IP:REQUEST_COUNT 是否大于 100
SecRule IP:REQUEST_COUNT "@gt 100" \
    "id:101,\
    phase:1,\
    deny,\
    status:429,\
    msg:'IP Rate Limit Exceeded - Too many requests',\
    logdata:'Current count: %{IP.REQUEST_COUNT}'"
```

### 2. 使用 `tx.user_id` 进行审计或逻辑控制

提取 `user_id` 后，通常用于日志审计或链式规则判断。

**场景：审计日志（记录谁干了什么）**

```apache
# --- 第一步：提取 user_id ---
SecRule ARGS:user_id "@rx ^(\d+)$" \
    "id:102,\
    phase:2,\
    pass,\
    nolog,\
    setvar:'tx.user_id=%{TX.1}'"

# --- 第二步：在审计规则中引用该变量 ---
SecRule REQUEST_URI "@contains /admin" \
    "id:103,\
    phase:2,\
    pass,\
    auditlog,\
    msg:'Admin Access Attempt',\
    logdata:'User ID: %{TX.USER_ID} accessed %{REQUEST_URI}'"
```
> **注意:** 在 `logdata` 中引用变量时，通常使用大写加点的格式（如 `%{TX.USER_ID}`），尽管定义时可能用的是小写。

### 3. 变量作用域区别

| 变量前缀 | 作用域 | 典型用途 | 注意事项 |
| :--- | :--- | :--- | :--- |
| **`IP:`** | **全局/持久** | 限流、暴力破解防护、临时黑名单 | 数据存储在共享内存中，重启服务或过期时间到了才会消失。 |
| **`TX:`** | **当前请求** | 提取参数、临时标记、跨规则传递数据 | 仅在当前 HTTP 请求处理过程中有效。请求结束，变量即销毁。 |

---

##  阶段说明

ModSecurity 处理请求分为 5 个阶段。如果规则未指定 `phase`，默认在 **Phase 2** 执行。

| 阶段 | 名称 | 说明 |
| :--- | :--- | :--- |
| **Phase 1** | 请求头 | 处理请求头数据。 |
| **Phase 2** | 请求体 | 处理请求体数据（**默认阶段**）。 |
| **Phase 3** | 响应头 | 处理响应头数据。 |
| **Phase 4** | 响应体 | 处理响应体数据。**注意：** 检测 `RESPONSE_BODY` 时必须指定此阶段。 |
| **Phase 5** | 日志 | 最后记录日志阶段。 |

> **提示:** 如果规则没有正确指定 `phase:4`，可能无法在响应内容中匹配到关键字。

---

##  规则示例

以下是一个指定了阶段的规则示例，用于检测特定 CVE 漏洞：

```apache
SecRule REQUEST_URI "@contains /api/gen/clients/" \
    "id:2023-27162,\
    phase:1,\
    deny,\
    status:403,\
    msg:'CVE-2023-27162 detected'"
```
