# Static Taint Analyzer (Java)

本地源代码污点分析服务：从数据入口（source）追踪不可信值向敏感汇点（sink）的传播路径，
产出**可复现、可审计**的分析结论。基于 Spring Boot，数据全部落在本地文件系统。

支持两种输入语言：

- **真实 Java 源代码**（`.java`，默认按目录提交，也可随请求内联提交）；
- 历史小型过程式 **DSL**（`.req`，原有能力保持不变）。

## 快速开始

```bash
mvn spring-boot:run          # 启动服务（默认端口 8080，数据目录 ./data）
mvn test                     # 运行全部自动化测试（离线可复现）
```

提交一次分析（内联文件，DSL/Java 均可）：

```bash
curl -X POST localhost:8080/api/projects/demo/analyses -H 'Content-Type: application/json' -d '{
  "jobId": "job-1",
  "rules": "{\"sources\":[{\"id\":\"user-input\",\"pattern\":\"readParam\",\"severity\":\"HIGH\"}],\"sinks\":[{\"id\":\"sql-exec\",\"pattern\":\"executeSql\",\"severity\":\"CRITICAL\"}],\"sanitizers\":[{\"id\":\"escape\",\"pattern\":\"escapeSql\"}]}",
  "files": {"a.req": "fn a() {\n  x = readParam(\"x\");\n  executeSql(x);\n}\n"}
}'
curl localhost:8080/api/projects/demo/analyses/job-1   # 查询任务状态
curl localhost:8080/api/projects/demo/findings         # 查询已提交结果
```

按**目录**提交一个 Java 项目（服务端递归扫描其中所有 `.java` 文件）：

```bash
curl -X POST localhost:8080/api/projects/demo/analyses -H 'Content-Type: application/json' -d '{
  "jobId": "job-java-1",
  "directory": "/abs/path/to/java-project",
  "rules": "{\"sources\":[{\"id\":\"http\",\"pattern\":\"com.acme.web.Http#param\"}],\"sinks\":[{\"id\":\"sql\",\"pattern\":\"com.acme.db.*\"}],\"sanitizers\":[]}"
}'
```

- 请求路径、方法与原有接口完全一致，仅新增**可选**字段 `directory`。
- `directory` 为服务端可读的**绝对路径**；键统一为相对扫描根、使用 `/` 分隔的路径
  （如 `com/acme/Foo.java`），多次扫描路径稳定可比较。
- `files`（内联）与 `directory` 可同时提供；路径冲突时目录内容优先。
- 作业会持久化目录路径，在执行时（以及崩溃恢复后）重新扫描，因此文件的
  **新增 / 修改 / 删除**都会在增量分析中体现；被删除文件出现在 `removedFiles`，
  未变化文件保持哈希不变并复用摘要缓存。

## 支持的 Java 语言范围与限制

解析器为 [JavaParser](https://javaparser.org)（Java 17 语法级），覆盖常见结构：

- 包声明、`import`（单类型、按需 `.*`、静态导入）；
- `class` / `interface` / `enum` / `record`、嵌套类型、匿名类、枚举常量体；
- 方法、构造器（含 `this(...)`/`super(...)`）、字段及字段初始化、静态/实例初始化块；
- 形参、局部变量（含 `var`、try-with-resources、catch 参数、增强 for 变量）；
- 控制流：`if/else`、`while`、`do-while`、`for`、增强 `for`、`switch`（含 `switch` 表达式）、
  `try/catch/finally`、`throw`、`assert`、`synchronized`、标号语句、`yield`；
- 表达式：字面量、标识符、各种二元/一元运算、三元、`instanceof`、强制转换、
  字符串拼接、数组访问/创建/初始化、Lambda、方法引用；
- 方法调用（限定/非限定/静态/链式）、对象创建 `new`、字段读写（`this.f`、`obj.f`、`Type.f`）；
- 继承与接口实现（沿父类/接口链解析）、方法重载（按参数元数筛选）、静态成员。

**限制（有意为之的保守近似，不是编译器）**：

- 不做完整 Java 类型检查与外部 classpath 解析；无法静态确定接收者类型时
  采用**保守连接**（调用结果继承实参/接收者污点），宁可多报不漏报。
- 仅建模**显式流**（赋值、拼接、传参/返回、字段、对象构造）；不建模隐式流、
  反射、动态加载、原生方法语义。
- 方法解析为结构化解析：项目类型 → 显式导入 → 同包 → 按需导入 → 嵌套类型 → `java.lang`。
- 传播是有限图上的最小不动点并集，循环、递归与别名天然有界且确定；
  重建路径长度上限 `MAX_PATH_LENGTH = 64`。
- 单个文件解析/降级失败只影响该文件，其余文件照常分析。

## 分析模型

分析分三个阶段，全程**确定性**（相同输入 + 相同规则 ⇒ 相同结果）：

1. **成员摘要（过程内）**：解析后把每个方法/构造器/字段初始化降级为流事实——
   赋值边、调用点（实参→形参、接收者→`this`、返回值→左值）、`return`、
   字段读（`field → 临时变量`）、字段写（`源 → field`）。清洗器调用切断污点。
   摘要只依赖本文件内容与规则，按 `sha256(文件内容)+规则哈希` 缓存。
2. **全程序图 + 污点传播（过程间）**：`ClassIndex` 负责跨类/跨包解析
   （导入、同包、继承链、重载元数）；节点为 `(成员, 变量)`，字段为全局节点
   `field:owner#name`（别名共享），另有合成节点 `$ret`、`$sink:...`。
   未解析的外部调用保守透传实参/接收者污点。传播为有限图上的 worklist 最小不动点，
   循环/递归终止、结果与迭代顺序无关。
3. **路径重建**：邻居排序的 BFS 取最短路径，长度上限 64，结果唯一可复现。

成员键形如 `pkg.C#m(argTypes)`，构造器为 `pkg.C#<init>(argTypes)`，因此重载与跨类调用可区分。

## 规则格式（声明式）

规则为 JSON，随分析请求提交；`pattern` 支持精确名与 `*` 通配。

- **DSL 调用**：按被调函数名匹配（如 `readParam`、`escape*`）。
- **Java 调用**：对同一调用点生成多个匹配令牌，任一命中即可：
  - 简单方法名：`param`
  - 完整限定方法：`com.acme.web.Http#param`、`com.acme.web.Http.param`
  - 拥有者 FQN：`com.acme.web.Http`
  - 简单类名形式：`Http#param`

  因此以下写法都合法：

  - `com.acme.web.Http#param`（精确到方法）
  - `com.acme.web.*`（包前缀通配，覆盖该包/子包下调用）
  - `Http#param`（简单类名）
  - `param`（仅按方法名，等价于 DSL 风格）

`severity`：`INFO < LOW < MEDIUM < HIGH < CRITICAL`（source 默认 MEDIUM，sink 默认 HIGH）。
规则集按 id 排序生成规范 JSON，其 SHA-256 为 `rulesHash`；规则变化会使全部文件摘要缓存失效，
每个提交各自绑定 `rulesHash`，绑定旧哈希的豁免在新规则下自动失效。

```json
{
  "sources":    [{"id": "http", "pattern": "com.acme.web.Http#param", "severity": "HIGH"}],
  "sinks":      [{"id": "sql",  "pattern": "com.acme.db.*",          "severity": "CRITICAL"}],
  "sanitizers": [{"id": "enc",  "pattern": "com.acme.Enc#encode"}]
}
```

## 结果语义

```json
{
  "commitId": "c…", "rulesHash": "…",
  "findings": [{
    "fingerprint": "…",
    "sourceRuleId": "http", "sinkRuleId": "sql",
    "severity": "CRITICAL",
    "status": "NEW",
    "path": [
      {"file":"src/com/acme/web/Handler.java","className":"com.acme.web.Handler",
       "method":"handle","function":"com.acme.web.Handler#handle(com.acme.web.Handler)",
       "variable":"name","line":12,"kind":"source"},
      {"file":"…","className":"…","method":"…","function":"…","variable":"…","line":…,"kind":"sink"}
    ]
  }],
  "removedFingerprints": ["…"],
  "suppressedFingerprints": ["…"],
  "parseFailures": [
    {"file":"com/acme/Broken.java","line":7,"code":"SYNTAX_ERROR","message":"…"}
  ],
  "removedFiles": ["com/acme/Old.java"],
  "stats": {"reusedFiles": 10, "reparsedFiles": 2, "failedFiles": 1, "removedFiles": 1}
}
```

每个路径步骤都带**真实源文件名、类名、方法名、变量名与行号**；DSL 结果中
`className`/`method` 退化为函数名以保持向后兼容。

### 解析失败语义

`parseFailures` 中每条记录都包含 `file`（文件名）、`line`（1 起始行号；无法定位为 `0`）、
`code`（机器可读错误码）与 `message`：

- `LEXICAL_ERROR`：词法错误（非法字符、未结束的字符串/字符字面量等，JavaParser `TokenMgrException`）；
- `SYNTAX_ERROR`：令牌无法构成合法 Java 语法；
- `IO_ERROR`：读取目录/文件失败；
- `INTERNAL_ERROR`：降级阶段的内部/暂不支持构造。

失败**不会**令作业失败或静默丢弃整批文件：成功文件照常产出 findings，失败文件计入
`stats.failedFiles`，相同内容下失败信息稳定，可在 `GET …/findings` 中核验。

其余语义（排序、去重、基线 diff、`NEW/UNCHANGED/REMOVED`、增量复用、豁免与审计、
并发一致性、崩溃恢复）与历史版本一致，且在目录/Java 输入下继续成立。

## HTTP API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/projects/{p}/analyses` | 提交分析（异步），body: `{files?, rules, jobId?, directory?}` |
| GET  | `/api/projects/{p}/analyses/{jobId}` | 任务状态：PENDING/RUNNING/COMMITTED/FAILED |
| GET  | `/api/projects/{p}/findings` | 当前已提交结果（含失败、移除文件、豁免压制视图） |
| GET  | `/api/projects/{p}/commits` | 提交历史 |
| GET  | `/api/projects/{p}/commits/{id}/findings` | 指定提交的结果 |
| POST | `/api/projects/{p}/exemptions` | 创建豁免 `{fingerprint, reason, createdBy, expiresAt?}` |
| GET  | `/api/projects/{p}/exemptions` | 豁免列表 |
| DELETE | `/api/projects/{p}/exemptions/{id}?actor=` | 撤销豁免 |
| GET  | `/api/projects/{p}/audit` | 审计日志 |

配置项：`taint.data-dir`（默认 `./data`）。

## 测试覆盖

`mvn test` 覆盖（离线可复现）：历史 DSL 的全部回归（跨函数、清洗器、循环/递归有界、
确定性、增量、规则隔离、豁免过期/撤销、审计、并发、崩溃恢复、REST 端到端），以及新增
Java 能力：

- 真实 Java 源码的跨方法、跨类、跨包传播；
- 字段读写与别名、对象构造把实参污点带入对象字段；
- 继承链与按元数的重载解析；
- 规则按完整限定名 / 通配包前缀匹配 Java 调用；
- 目录增量提交：新增 / 修改 / 删除（`removedFiles`）与未变化复用；
- 解析失败隔离、词法/语法错误码区分、其余文件正常分析；
- Java 输入下的并发提交链一致性与崩溃恢复（含目录作业重启重扫、幂等）；
- 多包大量文件（120+ 类）的有界完成时间。
