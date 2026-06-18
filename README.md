

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

在编写和配置规则时，变量的选用必须与规则的 `phase` 严格匹配。若在错误的阶段调用了未生成的变量（例如在 Phase 1 调用 `RESPONSE_BODY`），规则将失效或产生预期之外的错误。

| Phase ID | 阶段名称 | 推荐处理的变量类型 | 核心场景 |
| --- | --- | --- | --- |
| **phase:1** | 请求头 (Request Headers) | `REQUEST_URI`, `REQUEST_HEADERS`, `REMOTE_ADDR` | 阻断恶意扫描、IP 黑名单、恶意客户端（如 sqlmap） |
| **phase:2** | 请求体 (Request Body) | `ARGS`, `REQUEST_BODY`, `FILES` | 应用层攻击防御（SQLi, XSS, RCE, 恶意文件上传） |
| **phase:3** | 响应头 (Response Headers) | `RESPONSE_HEADERS`, `RESPONSE_STATUS` | 隐藏敏感敏感中间件信息、重定向拦截 |
| **phase:4** | 响应体 (Response Body) | `RESPONSE_BODY` | 敏感数据泄露防护（凭据、数据库堆栈、身份证号） |
| **phase:5** | 日志记录 (Logging) | 所有审计变量、计数器等 | 异步数据统计、持久化集合更新（此阶段不可中断请求） |

---
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

OWASP CRS 4.x 的核心设计理念是“多维度交叉检测 + 异常评分机制”。它不会孤立地只看某一个变量，而是把请求拆解得极其细致。以下梳理出的完整清单，涵盖了 CRS 4.x 实际规则库（包含 SQLi、XSS、LFI、RCE、解包缺陷等）中几乎所有的出场变量，并按照 CRS 的逻辑架构进行了归类。

---

### 🛡️ 一、 请求参数与负载核心域（OWASP CRS 命中率 > 60%）

这是 CRS 拦截 Web 攻击（SQL注入、XSS、命令注入等）最核心的武器库。CRS 4.x 极度依赖变量的组合（如 `ARGS|REQUEST_HEADERS`）来进行泛化泛洪式扫描。

| 变量名 | 可用阶段 | 在 CRS 4.x 中的核心用途与深度解析 | 典型规则示例 (模拟 CRS) |
| --- | --- | --- | --- |
| **`ARGS`** | 2, 3, 4, 5 | **CRS 的流量基石**。包含 GET 和 POST 的所有参数值。941(XSS) 和 942(SQLi) 中 80% 的规则首要检查此变量。 | `SecRule ARGS "@detectSQLi" "id:942100,phase:2,block"` |
| **`ARGS_GET`** | 1, 2, 3, 4, 5 | 仅包含 URL 中的查询参数。常用于在 Phase 1 进行轻量级的快速路径与参数基线防御。 | `SecRule ARGS_GET:id "@rx \D" "id:101,phase:1,deny"` |
| **`ARGS_POST`** | 2, 3, 4, 5 | 仅包含 Body 中的表单或 JSON/XML 解析后的参数。常配合请求头进行应用层逻辑检查。 | `SecRule ARGS_POST "@detectXSS" "id:941100,phase:2,block"` |
| **`ARGS_NAMES`** | 2, 3, 4, 5 | **所有参数的名称（键）**。CRS 用它来防御“参数污染攻击”或利用特殊参数名（如 `?cmd=xxx`）触发的代码执行。 | `SecRule ARGS_NAMES "@rx (?i)(cmd|exec|eval)" "id:932100,phase:2,block"` |
| **`ARGS_GET_NAMES`** | 1, 2, 3, 4, 5 | 仅 URL 查询参数的名称集合。 | `SecRule ARGS_GET_NAMES "@unconditionalMatch" "..."` |
| **`ARGS_POST_NAMES`** | 2, 3, 4, 5 | 仅 Body 参数的名称集合。 | `SecRule ARGS_POST_NAMES "@unconditionalMatch" "..."` |
| **`REQUEST_BODY`** | 2, 3, 4, 5 | 原始、未解析的请求体字符串。在处理非标准表单（如 Raw JSON, YAML, GraphQL）或针对反序列化漏洞、Java RCE 极其关键。 | `SecRule REQUEST_BODY "@contains 'objectConfiguration'" "id:933100"` |
| **`REQUEST_BODY_LENGTH`** | 2, 3, 4, 5 | 请求体的实际长度（字节数）。CRS 4.x 用它来做基线合规检查，防范缓冲区溢出或拒绝服务。 | `SecRule REQUEST_BODY_LENGTH "@gt 134217728" "id:920100"` |

---

### 🌐 二、 HTTP 协议与元数据域（协议违规与扫描器识别）

CRS 4.x 的 920 类规则（Protocol Violation）大量使用这类变量，用以确保请求完全符合 RFC 标准，直接过滤掉 90% 以上的粗劣自动化扫描工具。

| 变量名 | 可用阶段 | 在 CRS 4.x 中的核心用途与深度解析 | 典型规则示例 (模拟 CRS) |
| --- | --- | --- | --- |
| **`REQUEST_METHOD`** | 1, 2, 3, 4, 5 | HTTP 请求方法。CRS 严格限制非标方法（如 `PUT`, `DELETE`, `CONNECT`），非白名单直接控流。 | `SecRule REQUEST_METHOD "!@within GET POST HEAD" "id:920110,phase:1"` |
| **`REQUEST_URI`** | 1, 2, 3, 4, 5 | 包含查询字符串的完整相对路径。CRS 用其防御 URL 编码绕过、目录遍历（LFI/RFI）。 | `SecRule REQUEST_URI "@rx \.\./\.\." "id:930100,phase:1"` |
| **`REQUEST_FILENAME`** | 1, 2, 3, 4, 5 | **不包含查询参数的规范化路径**。专门用于精确匹配敏感文件后缀（如 `.bak`, `.sql`, `.env`）。 | `SecRule REQUEST_FILENAME "@rx \.(env|git|conf)$" "id:930110,phase:1"` |
| **`QUERY_STRING`** | 1, 2, 3, 4, 5 | 原始未解码的查询字符串。用于捕捉某些特定依赖原始字符对抗 WAF 规则绕过的 Web 攻击。 | `SecRule QUERY_STRING "@rx %00" "id:920120,phase:1,msg:'Null Byte'"` |
| **`REQUEST_PROTOCOL`** | 1, 2, 3, 4, 5 | 检查 HTTP 协议版本（如 `HTTP/1.1`, `HTTP/2`）。拦截伪造的无协议轻量级扫描。 | `SecRule REQUEST_PROTOCOL "!@rx ^HTTP/[12](\.[019])?$" "id:920130"` |
| **`URI`** | 1, 2, 3, 4, 5 | 在部分 WAF 架构中等同于 `REQUEST_URI`，作为标准字段备用。 | `SecRule URI "@contains '...'" "..."` |

---

### 📑 三、 请求头与会话状态域（防协议走私与撞库爬虫）

CRS 的 921（HTTP Request Smuggling）和 913（Crawler/Bot Detection）规则对这部分的依赖度极高。

| 变量名 | 可用阶段 | 在 CRS 4.x 中的核心用途与深度解析 | 典型规则示例 (模拟 CRS) |
| --- | --- | --- | --- |
| **`REQUEST_HEADERS`** | 1, 2, 3, 4, 5 | **请求头全集**。可以通过 `REQUEST_HEADERS:User-Agent` 或 `REQUEST_HEADERS:Host` 针对特定头进行多维指纹判定。 | `SecRule REQUEST_HEADERS:User-Agent "@contains nikto" "id:913100"` |
| **`REQUEST_HEADERS_NAMES`** | 1,2,3,4,5 | **所有请求头的键名**。核心用于检测 HTTP 走私（如不合规的 `Transfer-Encoding` 与 `Content-Length` 组合）。 | `SecRule REQUEST_HEADERS_NAMES "@contains 'Content-Length '" "id:921100"` |
| **`REQUEST_COOKIES`** | 2, 3, 4, 5 | 提取所有 Cookie 的值。CRS 将其视为潜在注入点，常与 `ARGS` 一起送入正则引擎匹配。 | `SecRule REQUEST_COOKIES "@rx (?:union|select)" "id:942110"` |
| **`REQUEST_COOKIES_NAMES`** | 2, 3, 4, 5 | 提取所有 Cookie 的键名，检查是否存在伪造会话键名或利用键名注入的漏洞。 | `SecRule REQUEST_COOKIES_NAMES "@rx [<>']" "id:941120"` |

---

### 📦 四、 数据解析、数据流与高级结构域（CRS 4.x 的高级特性）

CRS 4.x 引入了对复杂结构化数据（JSON/XML）以及多部分表单（Multipart）的深度原生审计变量。

| 变量名 | 可用阶段 | 在 CRS 4.x 中的核心用途与深度解析 | 典型规则示例 (模拟 CRS) |
| --- | --- | --- | --- |
| **`XML`** | 2, 3, 4, 5 | 当请求头为 `text/xml` 时，ModSecurity 自动解析为 XML 树，该变量可通过 XPath 轴精确定位元素，防范 XXE。 | `SecRule XML:/* "@unconditionalMatch" "id:941130,msg:'XML Check'"` |
| **`REQBODY_PROCESSOR`** | 2, 3, 4, 5 | 标明当前请求体是由哪个解析器处理的（如 `URLENCODED`, `MULTIPART`, `JSON`, `XML`）。CRS 用其做强制策略。 | `SecRule REQBODY_PROCESSOR "!@streq 'JSON'" "id:920140,msg:'Force JSON'"` |
| **`REQBODY_ERROR`** | 2, 3, 4, 5 | **极高频变量**。如果前端传了畸形的 JSON、未闭合的 XML 或损坏的 Multipart 边界，此变量置为 1。CRS 默认直接阻断，防止 WAF 后端解析差异导致的绕过。 | `SecRule REQBODY_ERROR "@eq 1" "id:920150,phase:2,deny,status:400"` |
| **`REQBODY_ERROR_MSG`** | 2, 3, 4, 5 | 存储解析失败的具体文本原因，CRS 会将其记录进审计日志。 | `logdata:'Parser failed due to: %{REQBODY_ERROR_MSG}'` |
| **`MULTIPART_BOUNDARY`** | 2, 3, 4, 5 | 多部分表单的分隔符。用于检测畸形边界造成的 WAF 逃逸攻击。 | `SecRule MULTIPART_BOUNDARY "@rx \s" "id:920160"` |
| **`MULTIPART_STRICT_ERROR`** | 2, 3, 4, 5 | 严格的 Multipart 协议依从性检查错误标志。 | `SecRule MULTIPART_STRICT_ERROR "@eq 1" "id:920170"` |
| **`MULTIPART_UNMATCHED_BOUNDARY`** | 2, 3, 4, 5 | 检测是否存在多余的、不匹配的表单边界（常用于逃逸检测）。 | `SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" "id:920180"` |
| **`INBOUND_DATA_ERROR`** | 2, 3, 4, 5 | 当请求大小超过了 `SecRequestBodyLimit` 配置时被触发。 | `SecRule INBOUND_DATA_ERROR "@eq 1" "id:920190"` |

---

### 📁 五、 文件上传安全专项变量（防 WebShell 投递）

专门针对 933 类规则（Restrict File Uploads），拦截通过头像上传、文档提交渗透恶意脚本的行为。

| 变量名 | 可用阶段 | 在 CRS 4.x 中的核心用途与深度解析 | 典型规则示例 (模拟 CRS) |
| --- | --- | --- | --- |
| **`FILES`** | 2, 3, 4, 5 | **上传文件的内容截断块**。CRS 通过它扫描文件流头部，检测是否包含 PHP 标签 `<?php` 或 JSP 指令。 | `SecRule FILES "@contains '<?php'" "id:933110,phase:2,block"` |
| **`FILES_NAMES`** | 2, 3, 4, 5 | 上传表单中 `input` 标签的 `name` 属性集合。 | `SecRule FILES_NAMES "@rx [<>']" "id:933120"` |
| **`FILES_SIZES`** | 2, 3, 4, 5 | 每个上传文件的实际大小。CRS 限制过大文件上传以抵御磁盘耗尽攻击。 | `SecRule FILES_SIZES "@gt 10485760" "id:933130,msg:'File > 10MB'"` |
| **`FILES_TMPNAMES`** | 2, 3, 4, 5 | 物理缓存在 WAF 服务器上的临时文件名。CRS 常利用该变量调用外部杀毒脚本（如 ClamAV）进行联动扫描。 | `SecRule FILES_TMPNAMES "@inspectFile /usr/bin/clamscan" "id:933140"` |
| **`FILES_TMP_CONTENT`** | 2, 3, 4, 5 | 允许直接对磁盘上的临时文件内容发起正则检索。 | `SecRule FILES_TMP_CONTENT "@rx eval\(base64_decode"` |

---

### 📤 六、 服务器响应与敏感数据泄露域（出站规则检测）

CRS 4.x 95x 类规则（Data Leakage）的核心。用于确保后端的严重报错、明文敏感数据（出站流量）不落入黑客手中。

| 变量名 | 可用阶段 | 在 CRS 4.x 中的核心用途与深度解析 | 典型规则示例 (模拟 CRS) |
| --- | --- | --- | --- |
| **`RESPONSE_STATUS`** | 3, 4, 5 | 后端业务系统返回的 HTTP 响应状态码。CRS 监控 500、502 状态码来感知后端崩溃。 | `SecRule RESPONSE_STATUS "^500$" "id:950100,phase:3,setvar:tx.leak=1"` |
| **`RESPONSE_HEADERS`** | 3, 4, 5 | 服务器的响应头集合。CRS 常借此重写、抹除破坏中间件敏感特征（如 `Server: Apache-Coyote/1.1`）。 | `SecRule RESPONSE_HEADERS:Server "@contains Tomcat" "id:950110"` |
| **`RESPONSE_HEADERS_NAMES`** | 3, 4, 5 | 响应头中所有键名的集合。 | `SecRule RESPONSE_HEADERS_NAMES "@contains 'X-Powered-By'" "..."` |
| **`RESPONSE_BODY`** | 4, 5 | **出站响应体源码**。必须开启 `SecResponseBodyAccess On`。CRS 用它检索大厂数据库（MySQL/Oracle）报错堆栈信息、内部绝对路径、高敏明文口令。 | `SecRule RESPONSE_BODY "@rx (?:Internal Server Error|Stack Trace)" "id:951100,phase:4,block"` |
| **`RESPONSE_CONTENT_TYPE`** | 3, 4, 5 | 响应媒体类型。CRS 利用它建立过滤器：**只对 `text/html` 进行内容扫描**，直接跳过图片、视频等二进制流，降低 CPU 开销。 | `SecRule RESPONSE_CONTENT_TYPE "!@streq 'text/html'" "id:950120,phase:3,nolog,noauditlog"` |
| **`OUTBOUND_DATA_ERROR`** | 4, 5 | 当由于业务数据过大，导致响应流量超出 `SecResponseBodyLimit` 时，此变量为 1。 | `SecRule OUTBOUND_DATA_ERROR "@eq 1" "id:950130,phase:4"` |

---

### 📡 七、 网络连接、地理与客户端基础设施域（威胁情报与准入控制）

| 变量名 | 可用阶段 | 在 CRS 4.x 中的核心用途与深度解析 | 典型规则示例 (模拟 CRS) |
| --- | --- | --- | --- |
| **`REMOTE_ADDR`** | 1, 2, 3, 4, 5 | 客户端源 IP。CRS 结合高级持久化集合（IP Collection）来实现跨请求的防暴力破解、高频 IP 直接封禁。 | `SecRule REMOTE_ADDR "@ipMatch 10.20.30.40" "id:901100,phase:1,deny"` |
| **`REMOTE_PORT`** | 1, 2, 3, 4, 5 | 客户端建立连接时随机映射的源端口。 | `SecRule REMOTE_PORT "@eq 0" "id:901110,msg:'Invalid Port'"` |
| **`SERVER_ADDR`** | 1, 2, 3, 4, 5 | 本地接收请求的虚 IP/真实服务器 IP。用于在多租户、多站点共用 WAF 场景下隔离防护策略。 | `SecRule SERVER_ADDR "@ipMatch 192.168.1.1" "id:901120"` |
| **`SERVER_NAME`** | 1, 2, 3, 4, 5 | 服务器主机名。 | `SecRule SERVER_NAME "@streq 'api.security.com'" "..."` |
| **`SERVER_PORT`** | 1, 2, 3, 4, 5 | 业务监听端口（例如 80, 443）。CRS 会检查端口与协议（如非 443 端口走了 HTTPS 加密隧道通道等异常基线）。 | `SecRule SERVER_PORT "!@within 80 443" "id:920200"` |
| **`GEO`** | 1, 2, 3, 4, 5 | 封装好的地理空间位置对象（子参数包括 `COUNTRY_CODE`, `REGION`, `CITY`）。CRS 4.x 广泛使用其构建区域合规阻断。 | `SecRule GEO:COUNTRY_CODE "@streq CN" "id:901200,phase:1,allow"` |

---

### 🎛️ 八、 状态、持久化、计数器与诊断控制域（CRS 异常评分架构的骨架）

这一组变量是 CRS 4.x 的灵魂所在。它们不代表直接的流量数据，而是规则引擎运行时的“记忆系统”。

```
[请求流入] ➡️ 匹配单条规则 ➡️ 触发变量累加：setvar:tx.anomaly_score=+5
                                              |
[评分判定] ⬅️ 最终核心规则拦截 ⬅️ 评估控制变量：SecRule TX:anomaly_score "@gt 20"

```

| 变量名 | 可用阶段 | 在 CRS 4.x 中的核心用途与深度解析 | 典型规则示例 (模拟 CRS) |
| --- | --- | --- | --- |
| **`TX`** | 1, 2, 3, 4, 5 | **核心控制变量群（单次事务生存期）**。CRS 的评分体系（Anomaly Score）完全依托于 `TX` 变量组（如 `TX:anomaly_score`、`TX:inbound_anomaly_score_threshold`）。所有的跨规则状态传递、拦截阈值定义均在此进行。 | `SecRule TX:anomaly_score "@gt TX:inbound_anomaly_score_threshold" "id:949110,phase:2,deny"` |
| **`IP`** | 1, 2, 3, 4, 5 | **持久化 IP 集合（跨请求全局生效）**。常用于 CC 防护或接口防刷。记录该 IP 在过去 N 秒内的报错次数或登录失败计数值。 | `SecRule IP:login_failures "@gt 10" "id:901300,phase:1,deny"` |
| **`SESSION`** | 2, 3, 4, 5 | 持久化会话变量。可绑定特定的 Session ID，跟踪某个已登录用户在生命周期内的异常行为轨迹。 | `SecAction "id:901310,setvar:session.attack_count=0"` |
| **`USER`** | 2, 3, 4, 5 | 持久化用户变量。与特定的用户名（Username）绑定，多用于防凭据倾倒、账号爆破攻击。 | `SecRule USER:bf_count "@gt 5" "id:901320"` |
| **`MATCHED_VAR`** | 任何匹配时刻 | **绝对高频**。代表当前规则中，**被正则或操作符命中时的那个具体字符串值**。常用于日志回显或 `logdata` 的精确定位。 | `logdata:'Detected malicious attack string: %{MATCHED_VAR}'` |
| **`MATCHED_VAR_NAME`** | 任何匹配时刻 | **绝对高频**。代表当前规则中，**被命中的那一个变量名/参数名**（例如告诉运维人员是 `ARGS:username` 还是 `REQUEST_HEADERS:X-Forwarded-For` 触发了拦截）。 | `logdata:'Attack field name located at: %{MATCHED_VAR_NAME}'` |
| **`MATCHED_VARS`** | 任何匹配时刻 | 当单条规则在多处资产同时命中时，该变量作为集合保存所有匹配到的文本数组。 | `SecRule MATCHED_VARS "@contains '...'" "..."` |
| **`MATCHED_VARS_NAMES`** | 任何匹配时刻 | 保存所有同时命中的变量名数组。 | `SecRule MATCHED_VARS_NAMES "@unconditionalMatch"` |
| **`ENV`** | 1, 2, 3, 4, 5 | 提取操作系统的环境变量（或 Apache/Nginx 的内部环境变量）。常用于结合底层架构做动态策略调整。 | `SecRule ENV:WAF_MODE "@streq 'BLOCK'" "..."` |
| **`HIGHEST_SEVERITY`** | 5 | 在单个请求的整个生命周期中，由于触发了多条不同的规则，记录其中**最严重的级别代码**（CRITICAL=2, ERROR=3, WARNING=4），CRS 在日志阶段以此变量自动进行高级威胁归类。 | `SecRule HIGHEST_SEVERITY "^2$" "id:980100,phase:5,setvar:ip.malicious=1"` |

---

### ⏱️ 九、 时间与审计诊断变量（时空控制与故障排查）

| 变量名 | 可用阶段 | 在 CRS 4.x 中的核心用途与深度解析 | 典型规则示例 (模拟 CRS) |
| --- | --- | --- | --- |
| **`TIME`** | 1, 2, 3, 4, 5 | 完整的服务器当前时间字符串（格式如 `Thu Jun 18 15:30:00 2026`）。 | `SecRule TIME "@rx ^Night" "..."` |
| **`TIME_EPOCH`** | 1, 2, 3, 4, 5 | Unix 时间戳（秒数）。在计算频率控制（如 1 秒内请求大于 100 次）时提供绝对的时间差分底座。 | `SecAction "id:901400,setvar:tx.current_time=%{TIME_EPOCH}"` |
| **`TIME_HOUR`** | 1, 2, 3, 4, 5 | 提取当前小时数 (00-23)。部分高安全基线项目用于实施“非办公时间核心管理后台只读/禁入”策略。 | `SecRule TIME_HOUR "!@within 09-18" "id:901410,phase:1"` |
| **`TIME_DAY`** | 1, 2, 3, 4, 5 | 提取当前是本月的第几天 (01-31)。 | `SecRule TIME_DAY "^01$" "..."` |
| **`TIME_MON`** | 1, 2, 3, 4, 5 | 提取当前月份 (00-11)。 | `SecRule TIME_MON "^05$" "..."` |
| **`TIME_YEAR`** | 1, 2, 3, 4, 5 | 提取当前年份（如 2026）。 | `SecRule TIME_YEAR "^2026$" "..."` |
| **`TIME_WDAY`** | 1, 2, 3, 4, 5 | 提取当前是星期几（0 为星期天，6 为星期六）。常用于周末自动化降级拦截。 | `SecRule TIME_WDAY "@within 0 6" "..."` |
| **`UNIQUE_ID`** | 1, 2, 3, 4, 5 | **底层模块自动为每次 HTTP 请求生成的全局唯一事务 ID 字符串**（24位）。CRS 将其强制写入每一次告警日志和阻断响应头，用于跨全栈（WAF-网关-微服务）的监控链路追踪。 | `setvar:tx.tracking_id=%{UNIQUE_ID}` |

---

### 💡 CRS 4.x 如何运用这近百个变量？

在 OWASP CRS 4.x 真正的复杂规则文件中，您常会看到如下的**组合拳**：

```apache
# 模拟一条 CRS 4.x 深度复合防护规则（跨越10余个变量联动）
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES|XML:/* "@rx (?i:union\s+all\s+select)" \
    "id:942150,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:lowercase,\
    msg:'SQL Injection Attack Detected via Multi-Variable Scan',\
    logdata:'Detected at Key: %{MATCHED_VAR_NAME}, Value: %{MATCHED_VAR}, ErrorState: %{REQBODY_ERROR}, UniqueID: %{UNIQUE_ID}',\
    setvar:tx.sql_injection_score=+15,\
    setvar:tx.anomaly_score=+15"

```

**总结**：这一套庞大的变量群组成了 ModSecurity 的神经传感网络。OWASP CRS 4.x 的强大之处并不在于正则表达式有多神秘，而在于它能够**同时调度这些参数名、参数值、请求体解析状态、网络层情报、持久化计数器以及时间上下文变量**，将其进行无缝的逻辑编织。
