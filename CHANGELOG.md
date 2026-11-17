# 更新日志（CyberLook-Scan 独立引擎）

本仓库是扫描引擎的独立发布物（主平台 `asset-platform` 内嵌同一份代码）。
版本号与主平台发布节奏同步，格式：语义化版本。

---

## [1.5.1] - 2026-11-17

### 修复

- **matcher 内的 `condition` 被忽略，导致大面积误报**：FingerprintHub 有 422 条规则
  把词间关系写在 matcher 内部（`{"type":"word","words":["a","b"],"condition":"and"}`），
  早期实现只认 HTTP item 级的 `matchers-condition`，内层 `and` 退化成 `or` ——
  只要页面沾上其中一个词就算命中。
  典型症状：`10.24.9.103:443` 页面里只有 `portal/login`，却被判成
  「中国电信 天翼宽带政企网关」，而该规则要求的 `loid_regist()` 根本没出现。
  现在加载时把这批 matcher 登记为"全词复核"，AC 命中后再逐词 `Contains` 校验。
  整段 `10.24.9.0/24` 对比：识别率不变（91%），但 `安恒云堡垒机 → 明御数据库审计`、
  `IBM HTTP Server → AMI MegaRAC` 这类具体错误被纠正。

### 新增

- **空壳 SPA 深度识别（`-deep-spa`，默认开）**：前端渲染型系统（管理台/网关/审计）
  首页只有 `<div id="app">` 和空标题，产品名由 JS 运行时从接口取回，纯静态抓取必然识别不出。
  新增 `svcid/spa.go`：按 `<base href>` 定位并抓同源 JS（≤2 个/≤1MB），
  从 JS 字面量抽只读信息类接口（`loginPage`/`customize`/`status`/`version`…，
  `login`/`captcha`/`delete` 等一律跳过），取 `platformName`/`platformIntroduction`
  等字段拼成补语料再匹配一次。单端口总预算 6 秒，只在空壳页面触发。
  实测识别出 `深信服 大模型安全护栏`（source=`spa-rule`），
  整段 C 类网段识别耗时 10.24s → 10.25s。
- **本地规则文件** `data/fingerprint/web_fingerprint_v4_local.json`：
  深信服大模型安全护栏、深信服统一门户(APEX)、AMI MegaRAC BMC 三条，
  与上游 `rules-update` 互不影响（文件名刻意匹配 `web_fingerprint_v4*` 的 glob）。

### 改进

- **TLS 证书 OU 纳入识别语料**：BMC 类设备的产品线只写在 OU（`O=AMI / OU=MEGARAC`），
  只看 CN/O 会漏。
- **标题与产品名空白归一**：`<title>` 里的换行/连续空格折叠成单空格，
  `normalizeProduct` 拆分后残留的多余空格也一并收掉
  （原样写进资产表会是 `AS2200G2 KWL 01   Login   Inspur AS2200G2`）。
- **占位产品名不再入库**：`Unknown`/`unidentified`/`N-A`/`ssl`/`tcp` 这类等于没识别，
  清空后走协议兜底，避免资产表出现"识别成功"的假象。

### 测试

- `svcid/spa_test.go`：SPA 判定、接口白名单（含"不得请求 login/verifyCode/delete"）、
  `platformName` 抽取、以及一条起本地假服务的端到端用例（壳页 → 按 base 抓 JS → 取接口）。
- `TestStrictWordAnd` / `TestWordOrDefault`：钉住"内层 and 必须全词命中、默认仍是 or"。

---

## [1.2.1] - 2026-11-12

### 修复

- **本地 fd / 端口耗尽不再被当成"端口关闭"（假阴性）**：connect 扫描里 dial 失败
  原来一律按"未开放"处理。当本机撞上 `EMFILE / ENFILE / ENOBUFS / EAGAIN / ENOMEM`
  （fd 不够、临时端口耗尽、内核缓冲不足）时，connect 是**几微秒内失败**，于是每个探针
  都被记成 closed，扫描器对外输出"该主机没有开放端口"——不报错、不留痕，是安全扫描器
  最致命的错（客户以为扫过了，其实一个包都没发出去）。
  现在：① `isLocalResourceErr` 用 `errors.As` 逐层解 `*net.OpError → *os.SyscallError →
  errno`（Windows 走文本兜底）；② 命中后**不记 closed**，让出并发许可、退让 200ms、
  重新排队重试，最多 3 次；③ 单轮内资源错误占比 > 0.5% → 返回
  `ErrLocalResourceExhausted`（调用方必须按失败处理，不得当成"无开放端口"），
  低于阈值只在 `Stats.LocalResErrs` 留痕。
  附带 `portscan/resource_test.go`：注入假 dialer 连续返回 EMFILE，断言
  「不判 closed」「确有重试」「最终返回资源错误」三条。

- **纯端口扫描不再白白解析 11MB 指纹规则**：`-identify` 未开启时不去加载
  FingerprintHub 全量规则（约 11MB JSON、首解析约 1.4s）。此前多进程/多并发同时首解析
  会把 CPU 打满，表现为"探针数不动、没有任何引擎输出"——只有顺着"缓存未命中 × 并发"
  才能想到。现在规则加载严格挂在识别开关上。

---

## [1.2.0] - 2026-11-11

### 新增

- 流式发现（`OnOpen`）：开放端口一发现就回调，不必等全量扫完。
- 取消即返部分结果：`ctx` 取消后返回已收集结果，不再整轮丢弃。
- 运行期调控 `Controls`：动态并发 / 动态超时 / 暂停 / 继续（atomic + sync.Cond，
  无 busy-wait），供上层做"限速、暂停、恢复"。

---

## [1.1.1] - 2026-11-10

### 修复

- `svcid.normalizeProduct` 按字节切首字符导致中文产品名乱码（U+FFFD）。
