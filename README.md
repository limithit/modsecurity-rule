# modsecurity-rule

ModSecurity 是一个用于检测和防止 Web 应用程序攻击的开源 Web 应用程序防火墙（WAF）。ModSecurity 可以使用一组规则来匹配和处理请求和响应。每个规则都有一个唯一的 ID，用于标识和引用该规则1。

ModSecurity 规则的 ID 范围没有严格的限制，但是有一些约定和建议。一般来说，ID 应该是一个六位数的数字，从 100000 到 9999992。不同的规则集可以使用不同的 ID 范围来避免冲突。例如，OWASP ModSecurity 核心规则集（CRS）使用 900000 到 999999 的范围1。自定义规则可以使用任何未被占用的 ID 范围，但建议避免与已有的规则集重叠。一种可能的方法是使用 100000 到 199999 的范围2。

ModSecurity 规则的执行顺序不是由 ID 决定的，而是由规则所在的阶段（phase）和文件加载的顺序决定的。ModSecurity 有五个阶段，分别是请求头（1）、请求体（2）、响应头（3）、响应体（4）和日志（5）。每个阶段内，规则按照文件加载的顺序执行。如果有多个文件包含相同阶段的规则，那么文件名按照字母顺序排序，先加载的文件中的规则先执行。

Read this in [English].(https://github.com/limithit/modsecurity-rule/edit/main/README_en.md)
