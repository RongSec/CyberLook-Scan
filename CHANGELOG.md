# 更新日志（CyberLook-Scan 独立引擎）

本仓库是扫描引擎的独立发布物（主平台 `asset-platform` 内嵌同一份代码）。
版本号与主平台发布节奏同步，格式：语义化版本。

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
