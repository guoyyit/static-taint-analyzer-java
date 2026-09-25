# Static Taint Analyzer (Java)

本地源代码污点分析服务：从数据入口（source）追踪不可信值向敏感汇点（sink）的传播路径，
产出**可复现、可审计**的分析结论。基于 Spring Boot，数据全部落在本地文件系统。

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
  "removedFingerprints": ["…"],    // 相对父提交消失的路径（基线对比）
  "suppressedFingerprints": ["…"]  // 当前被有效豁免压制的路径
}
```

- **排序**：严重度降序 → 路径长度升序 → 指纹字典序（全序，稳定）。
- **去重**：按 `fingerprint` 去重；相同输入与规则下同一传播路径的指纹必然相同。
- **基线对比**：每次提交与父提交按指纹 diff，得到 `NEW / UNCHANGED / REMOVED`；
  历史提交可通过 `/commits/{id}/findings` 完整回放。

## 增量分析

- 只有**内容哈希变化**的文件会重新解析与摘要（`stats.reparsedFiles`），未变化文件
  直接复用缓存摘要（`stats.reusedFiles`），重启后缓存从最近提交恢复、依然有效。
- 全局合成在合并后的摘要上完整重跑，因此**不会漏报**受跨文件影响的路径；
  未受影响的路径指纹不变，状态保持 `UNCHANGED`，**不会被误标为已变化**。

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
| POST | `/api/projects/{p}/analyses` | 提交分析（异步），body: `{files, rules, jobId?}` |
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

`mvn test` 共 22 个用例，覆盖：跨函数传播、清洗器拦截与绕过、循环/递归有界性、
结果确定性、增量复用与路径状态、规则变更隔离、豁免过期/撤销/规则失效、审计完整性、
并发读写一致性、并发提交链完整性、崩溃恢复与幂等、REST 端到端流程。
