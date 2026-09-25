# static-taint-analyzer-java

本地源代码污点分析服务：从数据入口（source）追踪不可信值向敏感汇点（sink）的传播路径，
提供可复现、可审计的分析结论。基于 Spring Boot + JavaParser，分析结果以不可变快照形式
原子提交，支持增量分析、豁免与基线对比、崩溃恢复。

## 构建与运行

```bash
mvn compile          # 编译
mvn test             # 运行全部测试
mvn spring-boot:run  # 启动服务（默认 8080 端口，数据目录 ./taint-data）
```

数据目录可通过 `taint.data-dir` 配置（`application.properties` 或命令行
`--taint.data-dir=/path/to/data`）。所有状态（快照、作业日志、规则、豁免、审计）都持久化在该目录下。

## 分析模型

### 程序建模

1. **解析**：`JavaModelBuilder` 用 JavaParser 解析目标目录下全部 `.java` 文件（按路径排序，
   保证确定性），生成 `ProgramModel`：方法表、调用图（按方法名 + 参数个数解析，双向索引）、
   字段读写索引、类字段类型表。
2. **方法内分析**：`TaintEngine` 将方法体作为语句序列解释执行，跟踪每个局部变量/参数的
   污点值（`TaintValue` = 来源规则集合 + 有序传播路径）。赋值、字符串拼接、条件表达式、
   三元、数组、对象构造等表达式按保守合并语义传播污点。
3. **跨函数传播**：先计算每个方法的**摘要**（`MethodSummary`：哪些参数流向返回值、返回值
   是否被内部 source 污染、污染了哪些字段），再在调用点应用摘要把实参污点映射到返回值。
   跨文件/跨模块传播通过全程序调用图自然完成。
4. **字段污点**：`this.x = tainted` 将字段记入全程序字段污点表，其他方法读取该字段时获得
   污点，实现跨方法、跨类的存储型传播。

### 有界性与确定性

| 场景 | 策略 |
| --- | --- |
| 循环 | 方法体整体重走直至不动点，最多 `MAX_METHOD_PASSES=8` 轮 |
| 递归 | 摘要不动点迭代，最多 `MAX_SUMMARY_ROUNDS=32` 轮；递归首次进入返回底值 |
| 字段污点 | 全程序不动点，最多 `MAX_FIELD_ROUNDS=8` 轮 |
| 路径长度 | `TaintValue.MAX_PATH_LENGTH=25`，超过后不再追加步骤 |
| 别名 | 赋值复制污点；`append/put/add/set/...` 等变更方法把实参污点并入接收者 |

所有集合使用有序结构（`TreeMap/TreeSet`），迭代顺序固定；相同输入 + 相同规则必然产生
完全相同的 findings（指纹、路径、排序均一致）。

**已知近似**（有意为之的保守取舍）：未做完整符号解析，调用按方法名+参数个数解析；
容器别名（`list2 = list1` 后对 `list2` 的写入不回流 `list1`）不精确；lambda 以共享环境
解释。这些近似保证有界与确定，且偏向多报而非漏报。

## 规则格式（声明式）

规则为 JSON 文档，通过 `PUT /api/rules` 更新：

```json
{
  "version": "1",
  "sources": [
    {"id": "http-param", "pattern": "javax.servlet.http.HttpServletRequest.getParameter",
     "risk": "HIGH", "message": "HTTP 入参"}
  ],
  "sinks": [
    {"id": "sql-exec", "pattern": "java.sql.Statement.execute*",
     "risk": "HIGH", "message": "SQL 注入"}
  ],
  "sanitizers": [
    {"id": "sql-escape", "pattern": "org.apache.commons.text.StringEscapeUtils.escapeSql",
     "risk": "LOW"}
  ]
}
```

- `pattern`：`全限定类名.方法名`，支持 `*`/`?` 通配；也接受 `简单类名.方法名` 或裸方法名。
- **source**：匹配的调用返回值被污染；若 pattern 匹配某个**方法签名**（如 `*.doGet`），
  则该方法的全部参数被视为污染源。
- **sink**：匹配调用点的任一实参或接收者被污染时产生 finding，风险等级取 sink 规则的 `risk`。
- **sanitizer**：匹配的调用返回干净值（杀死污点）。清洗器只作用于其返回值——对其它变量的
  清洗不会影响被污染变量（绕过场景会被继续报告）。
- 规则集内容计算规范 SHA-256 得到 `ruleHash`。**任何规则变更都会改变 hash**，触发下一次
  分析全量重算；旧规则结果与新规则结果分属不同快照，绝不混合；基于旧规则的豁免自动失效。

## 结果语义

### Finding

```json
{
  "fingerprint": "sha256(sink规则 + source规则 + 有序路径 + 汇点位置)",
  "sinkRuleId": "sql-exec",
  "sourceRuleId": "http-param",
  "risk": "HIGH",
  "path": [{"location": {"file": "...", "line": 1, "column": 1, "methodSignature": "..."},
            "description": "source http-param via getParameter"}, "..."],
  "sinkLocation": {"file": "...", "line": 5, "column": 9, "methodSignature": "demo.B#run(...)"},
  "sinkMethodSignature": "demo.B#run(...)",
  "ruleHash": "...",
  "firstSeenVersion": 1,
  "lastSeenVersion": 2
}
```

- **指纹去重**：同一指纹的路径只保留一条；指纹由内容决定，与运行次数无关 → 可复现。
- **排序**：风险等级降序（HIGH > MEDIUM > LOW），同级按指纹升序 → 输出稳定。
- **firstSeenVersion / lastSeenVersion**：首次/最近一次确认该路径的快照版本。增量分析中
  未受影响的路径保持 `firstSeenVersion` 不变（不会被误标为"已变化"）。

### 快照与并发可见性

- 每次分析提交一个不可变 `AnalysisSnapshot`（版本号单调递增）。提交协议：先写
  `snapshots/snapshot-N.json`（临时文件 + 原子 rename），再写 `current.json` 指针，
  最后更新作业日志 → 读取方永远只能看到某个**完整提交**的结果，看不到半成品。
- 分析作业在单后台线程串行执行；查询接口读当前快照，提交与查询可并发进行。

### 增量分析

- 按文件内容 SHA-256 检测变更；受影响方法 = 变更文件的方法 ∪ 其读取字段被变更方法写入
  的方法 ∪ 上述方法的传递调用者。
- 只重算受影响方法的摘要与 findings，未受影响 findings 原样保留（指纹、`firstSeen` 不变）。
- 规则 hash 变化或首次分析时自动全量重算。被删除方法产生的 findings 标记为 REMOVED，
  不会残留。

### 豁免与基线

- 豁免按指纹精确匹配，包含 `expiresAt` 与创建时的 `ruleHash`：
  - **过期即恢复检测**（查询时判定，无需重新分析）；
  - **规则变更即失效**（finding 的 `ruleHash` 与豁免不符）；
  - 豁免的创建、撤销、规则变更、每次分析提交都写入 `audit.jsonl`（只追加），可全程审计。
- 基线：`POST /api/baseline` 把当前快照版本设为基线；
  `GET /api/findings/new-since-baseline` 返回 `firstSeenVersion > 基线版本` 的新增路径。

### 崩溃恢复

- 每个作业在 `jobs/job-<id>.json` 中记录状态机 `PENDING → RUNNING → COMMITTED/FAILED`。
- 提交前崩溃：快照与指针均未写入，日志停留在 `RUNNING`；重启时 `recover()` 从最近一次
  已提交快照重新执行该作业——不重复分析已提交内容、不跳过变更、不留部分写入。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/analysis/jobs` | 提交分析 `{"sourceDir": "..."}`，返回 `jobId` |
| GET | `/api/analysis/jobs/{jobId}` | 查询作业状态 |
| POST | `/api/analysis/jobs/{jobId}/await` | 阻塞等待作业完成 |
| GET | `/api/snapshots/current` | 当前已提交快照 |
| GET | `/api/findings?minRisk=HIGH&includeExempted=false` | 查询 findings（排序、去重后） |
| GET | `/api/findings/{fingerprint}` | 单条 finding |
| GET/PUT | `/api/rules` | 查看/更新规则集 |
| POST | `/api/exemptions` | 创建豁免 `{"fingerprint","reason","createdBy","expiresAt"}` |
| GET | `/api/exemptions` | 列出豁免 |
| DELETE | `/api/exemptions/{id}` | 撤销豁免 |
| POST | `/api/baseline` | 将当前版本设为基线 |
| GET | `/api/findings/new-since-baseline` | 基线之后新增的 findings |
| GET | `/api/audit` | 审计日志 |

## 测试

`src/test/java` 覆盖需求要求的关键场景：

- `analysis/TaintEngineTest`：跨函数/跨文件传播、清洗器生效与绕过、循环递归的有界确定结果、别名传播；
- `incremental/IncrementalAnalysisTest`：增量更新（只重算受影响路径、不漏报、未变化路径不误标、重跑结果稳定）；
- `exemption/ExemptionTest`：豁免生效/过期恢复/规则变更恢复/审计/基线对比；
- `service/ConcurrencyCrashTest`：提交与查询并发（读方只见完整快照）、提交前崩溃后的恢复
  （无重复、无部分写入）、已提交工作不重复执行；
- `api/ApiIntegrationTest`：REST 全流程（规则 → 分析 → 查询 → 豁免 → 审计）。
