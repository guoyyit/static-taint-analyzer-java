# Static Taint Analyzer (Java)

本地污点分析服务：从数据入口（source）追踪不可信值向敏感汇点（sink）的传播路径，
产出**可复现、可审计**的分析结论。基于 Spring Boot，数据全部落在本地文件系统。

当前支持两类输入：

- **真实 Java 源代码（`.java`）**：跨方法、跨类、跨包的过程间污点分析（详见下文）。
- **历史 DSL（`.req` 等任意非 `.java` 键）**：原有小型过程式语言，接口与语义保持不变。

## 快速开始

```bash
mvn spring-boot:run          # 启动服务（默认端口 8080，数据目录 ./data）
mvn test                     # 运行全部自动化测试
```

提交一次分析：

```bash
curl -X POST localhost:8080/api/projects/demo/analyses -H 'Content-Type: application/json' -d '{
  "jobId": "job-1",
  "rules": "{\"sources\":[{\"id\":\"user-input\",\"pattern\":\"readParam\",\"severity\":\"HIGH\"}],\"sinks\":[{\"id\":\"sql-exec\",\"pattern\":\"executeSql\",\"severity\":\"CRITICAL\"}],\"sanitizers\":[{\"id\":\"escape\",\"pattern\":\"escapeSql\"}]}",
  "files": {"a.req": "fn a() {\n  x = readParam(\"x\");\n  executeSql(x);\n}\n"}
}'
curl localhost:8080/api/projects/demo/analyses/job-1   # 查询任务状态
curl localhost:8080/api/projects/demo/findings         # 查询已提交结果
```

## 被分析语言（DSL）

分析对象是一种小型过程式语言，每个文件可定义多个函数，函数名在项目内全局可见（跨模块调用按名字解析）：

```
fn handle(req) {              // 函数定义，参数即入口形参
  name = readParam("name");   // 赋值 / 调用
  q = "SELECT " + name;       // 二元拼接
  if (q) { log(q); } else { log("empty"); }
  while (name) { name = trim(name); }
  return q;
}
```

支持：`fn` 定义、赋值、表达式语句、`return`、`if/else`、`while`、字符串/数字字面量、
标识符、函数调用、`+` 拼接、`//` 注释。嵌套调用（如 `f(g(x))`）会被降级为临时变量。

## 被分析语言（Java）

服务可以直接解析真实的 `.java` 源文件（无需先编译），覆盖常见 Java 结构：

- `package` 声明、单类型/按需 `import`（含 `static` 导入）；
- `class` / `interface` / `enum` / `record` / 注解类型（`@interface` 体被跳过）、
  顶层与嵌套类型、修饰符与注解；
- 方法、构造器（含合成默认构造器）、字段与多变量声明、实例/静态初始化块；
- 局部变量（含 `var`）、形参、`this`/`super`；
- 控制流：`if/else`、`while`、`do-while`、传统 `for`、增强 `for`、`switch`、
  `try/catch/finally`（含 try-with-resources 与 multi-catch）、`throw`、
  `break/continue`、标号语句、`synchronized`、`assert`；
- 表达式：字符串/文本块/字符/数字字面量与转义、标识符、全部常见运算符、三元、
  `instanceof`（含模式变量）、强制转型、括号、方法引用与 lambda（见限制）、
  方法调用（简单/限定/`this`/`super`）、`new`（含匿名类，方法体参与分析）、
  数组创建/访问/初始化、变长参数。

### Java 污点语义

- **跨方法 / 跨类 / 跨包**：调用按“接收者类型 + 方法名 + 参数个数”在类模型中解析，
  沿 `extends`/`implements` 链查找；重载按参数个数区分，歧义按全限定名确定性决胜。
- **静态成员**：`T.f`、`T.m()` 经导入解析为全限定名；静态字段共享
  `$static.<全限定类名>.<字段>` 作用域，因此跨类读写同一静态字段可追踪。
- **字段与别名**：实例字段表示为 `$this.<字段>` 及 `a.b.c` 访问路径。
  `Order o = new Order(); Order x = o;` 这类引用拷贝建立双向别名，污点在
  `o.f` 与 `x.f` 间互通；跨方法调用时实参对象与形参（含构造器 `this` 与返回对象）
  按相同字段后缀双向连接。
- **字符串拼接与对象构造**：二元运算取操作数污点并集；`new T(args)` 追踪实参到
  构造器，并把构造期 `this` 的污点带回新对象变量。
- **循环 / 递归 / 别名**：传播仍是有限图上的最小不动点并集，天然有界、确定；
  路径重建步数上限 `MAX_PATH_LENGTH = 64`。
- 只建模显式流，不建模隐式流。外部/不可解析类型的调用按“恒等函数”保守透传实参污点，
  但项目内已定义的同名方法不会被误当作外部透传。

### 支持范围与限制

- 不做完整 Java 类型检查：泛型按原始类型处理，不做类型参数推断；方法分派基于
  名字 + 参数个数，不依据形参重载类型精确选择（同名同参数个数的重载按全限定名
  确定性地选择一个）。
- **lambda/方法引用的声明可解析，但其通过函数式接口的间接回调不被调用建模**；
  反射、动态代理、原生方法不跟踪。
- 流不敏感、路径不敏感；数组不区分下标（`arr[i]` 合并到数组对象本身）。
- 个别文件解析失败不影响其余文件（见“解析失败语义”）；个别不支持的语法特性只会
  让该文件失败，不会阻塞整个项目。

## 分析模型

分析分三个阶段，全程**确定性**（相同输入 + 相同规则 ⇒ 相同结果）：

1. **函数摘要（过程内）**：每个函数独立提取流事实——赋值边、调用点（实参→形参、
   返回值→左值）、return、source 注入点、sink 暴露点。清洗器（sanitizer）调用
   **不产生**流边（污点被切断）。摘要只依赖本文件内容与规则，因此可按
   `sha256(文件内容)+规则哈希` 缓存，是增量分析的基础。
2. **全局流图 + 污点传播（过程间）**：把摘要拼成全程序流图。节点为
   `(函数, 变量)`，另有合成节点 `$ret`（返回值）与 `$sink:<行>:<规则>`（汇点）。
   调用边连接实参与形参、返回值与左值；未解析的外部调用按保守策略把实参污点
   透传到返回值。传播是有限图上的**最小不动点并集**，因此：
   - **循环 / 递归**：天然终止，不会栈溢出或发散；
   - **别名**：`a = b` 即污点复制，两个名字共享同一污点集；
   - 结果与迭代顺序无关。
3. **路径重建**：对每个 (source, sink) 标签对，在流图上做**邻居排序的 BFS**
   取最短路径，路径长度上限 64 步（`MAX_PATH_LENGTH`），保证有界且唯一。

只建模**显式流**（赋值、拼接、调用传参/返回），不建模隐式流（条件分支不影响污点）。

## 规则格式（声明式）

规则为 JSON，随分析请求提交；`pattern` 匹配被调函数名，支持精确名或 `*` 通配：

```json
{
  "sources":    [{"id": "user-input", "pattern": "readParam",  "severity": "HIGH"}],
  "sinks":      [{"id": "sql-exec",   "pattern": "executeSql", "severity": "CRITICAL"}],
  "sanitizers": [{"id": "escape",     "pattern": "escape*"}]
}
```

- `severity`：`INFO < LOW < MEDIUM < HIGH < CRITICAL`（source 默认 MEDIUM，sink 默认 HIGH）。
- 规则集按 id 排序后生成**规范 JSON**，其 SHA-256 为 `rulesHash`，绑定到每次提交。
- **规则变更不会混淆新旧结果**：规则变化会使全部文件摘要缓存失效（重新分析），
  每个提交各自记录 `rulesHash`；绑定旧规则哈希的豁免在新规则下自动失效。

### Java 规则匹配语法

对 Java 调用，每条规则的 `pattern` 会依次尝试三种名字形式，任一命中即生效：

1. 全限定方法名：`com.acme.db.Dao#execute`（构造器为 `com.acme.Foo#<init>`）；
2. 点限定静态/实例拼写：`com.acme.db.Dao.execute`（便于用包前缀写通配规则）；
3. 裸方法名：`execute`。

`*` 是通配符（映射为正则 `.*`），可出现在任意位置。示例：

```json
{
  "sources":    [{"id": "req",  "pattern": "com.acme.web.*Request#getParam"}],
  "sinks":      [{"id": "jdbc", "pattern": "*.execute", "severity": "CRITICAL"},
                 {"id": "all-db","pattern": "com.acme.db.*", "severity": "HIGH"}],
  "sanitizers": [{"id": "esc",  "pattern": "*.escapeSql"}]
}
```

- source 在“方法返回值”处注入污点；sink 在方法的形参处暴露（路径会经过真实的
  被调类/方法）；清洗器命中时该调用不产生任何流边（污点被切断）。
- 无法解析到项目内方法的调用（如库方法）仍按上述三种拼写做规则匹配，因此
  `java.sql.Statement#executeQuery` 这类外部汇点/源点规则同样生效。
- DSL 输入只使用第 3 种（裸函数名）形式，历史规则行为不变。

## 结果语义

```json
{
  "commitId": "c…", "rulesHash": "…",
  "findings": [{
    "fingerprint": "…",            // 路径规范签名的 SHA-256，稳定可复现
    "sourceRuleId": "user-input", "sinkRuleId": "sql-exec",
    "severity": "CRITICAL",        // max(source, sink) 严重度
    "status": "NEW",               // NEW | UNCHANGED（相对父提交）
    "path": [                      // source → … → sink 的完整传播路径
      {"file":"a.req","function":"a","variable":"x","line":2,"kind":"source"},
      {"file":"a.req","function":"a","variable":"executeSql","line":3,"kind":"sink"}
    ]
  }],
  "removedFingerprints": ["…"],    // 相对父提交消失的路径指纹（基线对比）
  "suppressedFingerprints": ["…"], // 当前被有效豁免压制的路径
  "removedFiles": ["src/B.java"],  // 本次不再存在的文件逻辑路径
  "addedFiles":   ["src/C.java"],  // 本次新增的文件逻辑路径
  "parseFailures": [               // 解析失败但被隔离的文件（不阻断其它文件）
    {"file":"src/Bad.java","line":3,"reason":"SYNTAX","message":"expected RPAREN …"}
  ],
  "reusedFiles": 12, "reparsedFiles": 2, "unchangedFiles": 12,
  "failedFiles": 1, "totalFiles": 15
}
```

- **排序**：严重度降序 → 路径长度升序 → 指纹字典序（全序，稳定）。
- **去重**：按 `fingerprint` 去重；相同输入与规则下同一传播路径的指纹必然相同。
- **基线对比**：每次提交与父提交按指纹 diff，得到 `NEW / UNCHANGED / REMOVED`；
  历史提交可通过 `/commits/{id}/findings` 完整回放。
- Java 路径的每一步都带真实的源文件名、`className`（全限定类名；静态字段为
  `$static`，DSL 为空串）、`function`、`variable` 与源码行号。

### 解析失败语义

单个文件解析失败**不会**让整批提交失败，也不会被静默丢弃：

- 该文件不产生摘要/结论，但同批其它文件照常分析；
- 失败以 `parseFailures` 返回并持久化进提交，每条包含逻辑路径 `file`、1-based `line`、
  机器可读 `reason` 与人类可读 `message`；
- `reason` 区分失败原因：
  - `LEXICAL` —— 词法错误（非法字符、未结束的字符串/注释、错误转义等）；
  - `SYNTAX` —— token 合法但不符合 Java 语法（括号不匹配、缺少分隔符等）；
  - `UNSUPPORTED` —— 语法可识别但分析器显式不支持；
  - `IO` —— 目录扫描时的读取错误。
- 增量分析中，未修改的失败文件沿用缓存的失败记录（计入 `failedFiles`），修改后重试。

验证方式：`GET /api/projects/{p}/findings` 的 `parseFailures` 数组；文件与行号可直接
在对应源文件中定位，`reason` 可用于区分“源码写错了”与“工具暂不支持”。

## 增量分析

- 只有**内容哈希变化**的文件会重新解析与摘要（`stats.reparsedFiles`），未变化文件
  直接复用缓存摘要（`stats.reusedFiles`），重启后缓存从最近提交恢复、依然有效。
- 全局合成在合并后的摘要上完整重跑，因此**不会漏报**受跨文件影响的路径；
  未受影响的路径指纹不变，状态保持 `UNCHANGED`，**不会被误标为已变化**。

### 目录提交

提交体新增可选字段 `directories`：一个或多个**服务端可读的本地目录**。服务递归
发现其中所有 `.java` 文件（跳过不可读条目），以相对目录根的 `/` 分隔逻辑路径作为
文件键，并与内联 `files` 合并（同名键以内联 `files` 为准）。接口路径与请求方式不变：

```bash
curl -X POST localhost:8080/api/projects/demo/analyses \
  -H 'Content-Type: application/json' -d '{
    "jobId": "scan-1",
    "directories": ["/path/to/my-java-project/src/main/java"],
    "files": {},
    "rules": "{\"sources\":[...],\"sinks\":[...],\"sanitizers\":[...]}"
  }'
```

后续提交重新扫描同一目录即可做增量：

- 新增文件出现在 `addedFiles`，相关路径标记为 `NEW`；
- 修改的文件计入 `reparsedFiles`，受影响路径更新、不受影响路径保持 `UNCHANGED`；
- 删除的文件计入 `removedFiles`，其路径指纹进入 `removedFingerprints`。

## 豁免与审计

- 豁免绑定 `(fingerprint, rulesHash)`，可设 `expiresAt`；仅当未撤销、未过期、
  且规则哈希与当前提交一致时才压制告警。**豁免过期、被撤销或规则变更后自动恢复检测**。
- 所有变更写入只追加的 `audit.log`：`ANALYSIS_COMMITTED`、`RULES_CHANGED`、
  `EXEMPTION_CREATED`、`EXEMPTION_REVOKED`，带单调序号、时间与操作者。

## 并发与一致性

- 单个后台写线程串行执行任务；读请求只读取 `HEAD` 指向的**不可变提交快照**，
  因此提交与查询可并发进行，读取方永远看不到半成品或中间状态。
- 提交协议：写 `journal/<id>.tmp` → 原子 rename 到 `commits/<id>` → 原子替换 `HEAD`。

## 中断与崩溃恢复

- 任务先持久化到 `jobs/<jobId>.json` 再执行；提交 id 由 `(jobId, parentId, rulesHash)`
  决定，**幂等**。
- 重启时 `recoverAll()`：清理半成品 journal、校验 `HEAD`、扫描任务文件——
  已提交的任务绝不重跑；`PENDING/RUNNING` 的任务从最近一次已提交位置继续执行，
  不重复分析、不跳过变更、不留部分写入。

## HTTP API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/projects/{p}/analyses` | 提交分析（异步），body: `{files, rules, jobId?, directories?}`；`directories` 为待递归扫描的 `.java` 目录数组 |
| GET  | `/api/projects/{p}/analyses/{jobId}` | 任务状态：PENDING/RUNNING/COMMITTED/FAILED |
| GET  | `/api/projects/{p}/findings` | 当前已提交结果（含豁免压制视图） |
| GET  | `/api/projects/{p}/commits` | 提交历史 |
| GET  | `/api/projects/{p}/commits/{id}/findings` | 指定提交的结果 |
| POST | `/api/projects/{p}/exemptions` | 创建豁免 `{fingerprint, reason, createdBy, expiresAt?}` |
| GET  | `/api/projects/{p}/exemptions` | 豁免列表 |
| DELETE | `/api/projects/{p}/exemptions/{id}?actor=` | 撤销豁免 |
| GET  | `/api/projects/{p}/audit` | 审计日志 |

配置项：`taint.data-dir`（默认 `./data`）。

## 测试覆盖

`mvn test` 共 41 个用例，在保留全部历史 DSL 用例的基础上新增 Java 相关覆盖：

- Java 解析：包/导入/类/接口/字段/方法/构造器/控制流/表达式，词法与语法错误的
  文件/行号/原因区分；
- Java 污点：跨方法、跨类、跨包传播，字段读写与别名，字符串拼接与对象构造，
  继承与重载解析，静态成员跨类共享，清洗器切断，确定性与路径有界；
- 目录提交：递归发现 `.java`、新增/修改/删除的增量体现与删除路径报告；
- 解析失败隔离：单文件失败不影响其余文件，失败原因可区分；
- Java 输入下的并发提交链一致性、崩溃恢复幂等、重启后增量缓存复用；
- 大文件（深度循环/递归）与多包多文件项目的有界完成时间；
- 目录提交、失败信息与路径字段（文件/类/方法/行号）的 REST 端到端验证。
