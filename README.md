# modsecurity-rule
## 生成一些常用规则，如防止爆力破解账密、log4j2以及近几年CVE漏洞  
ModSecurity 是一个用于检测和防止 Web 应用程序攻击的开源 Web 应用程序防火墙（WAF）。ModSecurity 可以使用一组规则来匹配和处理请求和响应。每个规则都有一个唯一的 ID，用于标识和引用该规则1。

ModSecurity 规则的 ID 范围没有严格的限制，但是有一些约定和建议。一般来说，ID 应该是一个六位数的数字，从 100000 到 9999992。不同的规则集可以使用不同的 ID 范围来避免冲突。例如，OWASP ModSecurity 核心规则集（CRS）使用 900000 到 999999 的范围1。自定义规则可以使用任何未被占用的 ID 范围，但建议避免与已有的规则集重叠。一种可能的方法是使用 100000 到 199999 的范围2。

ModSecurity 规则的执行顺序不是由 ID 决定的，而是由规则所在的阶段（phase）和文件加载的顺序决定的。ModSecurity 有五个阶段，分别是请求头（1）、请求体（2）、响应头（3）、响应体（4）和日志（5）。每个阶段内，规则按照文件加载的顺序执行。如果有多个文件包含相同阶段的规则，那么文件名按照字母顺序排序，先加载的文件中的规则先执行。`如果没有指定在哪个阶段检查，它就会在所有的阶段都检查。如果你想要限制它只在某个阶段检查，可以在规则的参数中添加一个phase参数，例如：`

```SecRule REQUEST_URI "@contains /api/gen/clients/" "id:2023-27162,deny,status:403,msg:'CVE-2023-27162 detected',phase:1"```


Read this in [English](README_en.md).*

###  Test on libmodsecurity.so.3.0.8 & ModSecurity-nginx v1.0.3

## 部分规则简介
@pm: `它的含义是“partial match”。它用于匹配变量的值是否包含给定的字符串列表中的任意一个。例如，@pm bot spider crawler表示匹配变量的值是否包含bot、spider或crawler。您可以使用|符号来分隔字符串列表中的元素。您也可以使用文件名作为参数，例如@pmFromFile bad-user-agents.txt，表示匹配变量的值是否包含文件bad-user-agents.txt中列出的任意一个字符串。`

@pmFromFile:`它的含义是“partial match from file”。它用于匹配变量的值是否包含给定文件中列出的任意一个字符串。例如，@pmFromFile bad-user-agents.txt表示匹配变量的值是否包含文件bad-user-agents.txt中列出的任意一个字符串。可以使用任意存在的文件名作为参数，但是要注意文件中每行只能有一个字符串，并且要注意区分大小写。`

@contains: `它的含义是“contains”。它用于匹配变量的值是否包含给定的字符串。例如，@contains admin表示匹配变量的值是否包含admin。可以使用任意长度的字符串作为参数，但是不能使用正则表达式或通配符。如果想要匹配多个字符串，可以使用@pm或@pmFromFile操作符。`

@rx: `它的含义是“regular expression”。它用于匹配变量的值是否符合给定的正则表达式。例如，@rx ^[a-z]+$表示匹配变量的值是否由小写字母组成。可以使用任意合法的正则表达式作为参数，但是要注意转义特殊字符。如果想要匹配多个正则表达式，可以使用@rxFromFile操作符。`

@streq: `它的含义是“string equals”。它用于匹配变量的值是否与给定的字符串完全相等。例如，@streq GET表示匹配变量的值是否为GET。可以使用任意长度的字符串作为参数，但是要注意区分大小写。如果想要匹配多个字符串，可以使用@eq或@within操作符。`

@eq: `它的含义是“equals”。它用于匹配变量的值是否与给定的数字或字符串列表中的任意一个相等。例如，@eq 200表示匹配变量的值是否为200。@eq GET POST表示匹配变量的值是否为GET或POST。可以使用任意合法的数字或字符串作为参数，但是要注意区分大小写。`

@within: `它的含义是“within”。它用于匹配变量的值是否包含在给定的字符串列表中。例如，@within admin root表示匹配变量的值是否为admin或root。@within GET POST PUT DELETE表示匹配变量的值是否为GET、POST、PUT或DELETE。可以使用任意长度的字符串作为参数，但是要注意区分大小写。`

@gt: `它的含义是“greater than”。它用于匹配变量的值是否大于给定的数字。例如，@gt 100表示匹配变量的值是否大于100。可以使用任意合法的数字作为参数，但是不能使用字符串。`

@lt:`它的含义是“less than”。它用于匹配变量的值是否小于给定的数字。例如，@lt 100表示匹配变量的值是否小于100。可以使用任意合法的数字作为参数，但是不能使用字符串。`

@ge: `它的含义是“greater than or equal”。它用于匹配变量的值是否大于或等于给定的数字。例如，@ge 100表示匹配变量的值是否大于或等于100。可以使用任意合法的数字作为参数，但是不能使用字符串。`

@beginsWith: `它的含义是“begins with”。它用于匹配变量的值是否以给定的字符串开头。例如，@beginsWith http表示匹配变量的值是否以http开头。可以使用任意长度的字符串作为参数，但是要注意区分大小写。`

@endsWith: `它的含义是“ends with”。它用于匹配变量的值是否以给定的字符串结尾。例如，@endsWith .php表示匹配变量的值是否以.php结尾。可以使用任意长度的字符串作为参数，但是要注意区分大小写。`

@ipMatch: `它的含义是“IP match”。它用于匹配变量的值是否与给定的IP地址或子网相匹配。例如，@ipMatch 192.168.0.1表示匹配变量的值是否为192.168.0.1。@ipMatch 192.168.0.0/24表示匹配变量的值是否属于192.168.0.0/24子网。可以使用任意合法的IP地址或子网作为参数，但是不能使用域名或主机名。`

t:none `它的含义是“no transformation”。它用于取消应用于变量的值的所有转换函数。转换函数是一些可以修改变量的值的函数，例如将大写字母转换为小写字母，或者解码URL编码。t:none通常用于覆盖全局或父级规则中设置的转换函数。`

t:lowercase `它的含义是“lowercase transformation”。它用于将变量的值转换为小写字母。这样可以防止大小写绕过，例如admin和Admin被视为相同的值。t:lowercase通常用于增强规则的匹配能力。`

TX:`它的含义是“transaction”。它用于存储和访问规则执行过程中产生或修改的数据。例如，TX:foo表示访问或设置名为foo的事务数据。可以使用任意合法的名称作为参数，但是要注意区分大小写。`

@validateByteRange:`它的含义是“validate byte range”。它用于验证变量的值是否只包含给定范围内的字节。例如，@validateByteRange 32-126表示验证变量的值是否只包含ASCII码为32到126之间的字节。可以使用任意合法的字节范围作为参数，但是要注意使用连字符分隔起始和结束字节，并且要注意按照升序排列。`

@detectXSS: `它的含义是“detect cross-site scripting”。它用于检测变量的值是否包含XSS攻击向量。例如，@detectXSS表示检测变量的值是否包含XSS攻击向量。不需要提供任何参数，但是要注意这个操作符可能会产生一些误报或漏报。`

@detectSQLi:`它的含义是“detect SQL injection”。它用于检测变量的值是否包含SQL注入攻击向量。例如，@detectSQLi表示检测变量的值是否包含SQL注入攻击向量。不需要提供任何参数，但是要注意这个操作符可能会产生一些误报或漏报。`

@validateUrlEncoding：`它的含义是“validate URL encoding”。它用于验证变量的值是否符合有效的URL编码格式。例如，@validateUrlEncoding表示验证变量的值是否符合有效的URL编码格式。不需要提供任何参数，但是要注意这个操作符可能会拦截一些合法的请求，例如包含双字节字符的请求。`

setvar `设置变量`

expirevar `变量过期` 

## 提示
在 ModSecurity 规则中，phase 参数是可选的。如果未指定，默认规则会在 Phase 2（请求处理阶段）执行。

然而，在处理`RESPONSE_BODY`时，通常需要明确指定在 Phase 4（响应处理阶段）执行，因为这是服务器在返回响应体的时候处理的阶段。

如果规则没有正确指定 Phase 4 可能不会在响应内容中匹配到关键字。
