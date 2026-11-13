# CyberLook-Scan

自研端口扫描 + 全量指纹识别引擎（connect 扫描 · FingerprintHub 15388 条规则 · GPL-3.0）。

- **零第三方依赖**：只用 Go 标准库（`net`、`net/http`、`encoding/json`、`regexp` …），`go get` 一次都不会发生。
- **准确率优先**：TCP connect 全连接扫描（三次握手成功才算开放），不玩 SYN 半开——SYN 在丢包/防火墙静默丢弃下会把开放端口误判成关闭，属于事后不可回溯的静默漏报。
- **吞吐靠并发**：4096 并发 × 500ms ≈ 8000 探针/秒。关闭端口立刻回 RST，不受超时拖累。
- **全量规则**：内置 [0x727/FingerprintHub](https://github.com/0x727/FingerprintHub)（MIT）web 3450 条 + service 11938 条，Aho-Corasick 一次扫描完成 word 匹配。


## 这个模块也被平台依赖（改动须知）

平台 `CyberLook` **不再复制** `portscan` / `svcid` 源码，而是 `require` 本模块的 tag。
也就是说这里改一行，平台和你自己编的 CLI 会同时生效 —— 功能与性能天然一致，
代价是这里必须遵守两条约束：

1. **保持 API 稳定**：`portscan.Options/Result/Stats/Controls/ParsePorts/ErrLocalResourceExhausted`、
   `svcid.RuleSet/Load/BuildServiceProbes/...` 的签名与语义不要随意改（要改就发 major 版本）。
2. **每次改动都要打 tag**：`git tag -a vX.Y.Z && git push origin main --tags`，
   然后在平台里 `go get github.com/RongSec/CyberLook-Scan@vX.Y.Z && go mod tidy`。
   平台侧有 `scripts/check-engine-version.sh` 会比对锁定版本与最新 tag，漂了会报出来。

只改文档/CI 不必打 tag；改了扫描逻辑、指纹识别、存活探测就必须打。


## 构建

需要 Go 1.26+：

```bash
go build ./...
go build -trimpath -ldflags="-s -w" -o cyberlook-scan.exe ./cmd/cyberlook-scan
```

## 快速上手

```bash
# Top100 端口扫描 + 服务识别
cyberlook-scan -targets 10.24.20.0/24 -ports top100 -identify

# 先存活探测，再只对活主机做端口扫描 + 识别（大网段推荐，省掉大量死主机超时）
cyberlook-scan -targets 10.24.20.0/24 -ports top100 -alive -identify

# 只看哪些主机活着，不做端口扫描与识别
cyberlook-scan -targets 10.24.20.0/24 -alive-only -out alive.json

# 全端口扫描，只出结果不识别
cyberlook-scan -targets 10.24.2.65 -ports 1-65535 -concurrency 2000

# 指定规则：目录 / 单个文件 / 逗号分隔混合
cyberlook-scan -targets 10.24.2.65 -identify -rules data/fingerprint
cyberlook-scan -targets 10.24.2.65 -identify -rules /opt/rules/web_fingerprint_v4.json
cyberlook-scan -targets 10.24.2.65 -identify -rules /opt/rules/web.json,/opt/more/rules

# 复用既有扫描结果，只重跑识别
cyberlook-scan -reidentify result.json -out result2.json

# 把规则更新到上游最新版
cyberlook-scan rules-update -rules data/fingerprint
```

## 参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-targets` | — | 目标：`IP` / `CIDR` / 区间（`10.0.0.1-20`、`10.0.0.1-10.0.0.20`）/ 逗号分隔 / `@file` 从文件读取 |
| `-ports` | `top100` | 端口表达式：`top100` / `top1000` / `1-65535` / `22,80,443` / 混合 |
| `-exclude` | — | 排除目标，语法同 `-targets` |
| `-concurrency` | `1500` | 并发连接数 |
| `-timeout` | `1500` | 单端口超时毫秒；`<100` 按秒解释 |
| `-alive` | `false` | 扫描前先做存活探测，**只对存活主机做端口扫描** |
| `-alive-only` | `false` | 纯存活探测：只输出活主机清单，不做端口扫描、不走 `-identify`。与 `-alive` 同时给时本项优先 |
| `-alive-ports` | `80,443,22,445,3389,8080,8443,135,139,3306` | 存活探测端口，语法同 `-ports` |
| `-alive-timeout` | `400` | 存活探测单端口超时毫秒 |
| `-identify` | `false` | 扫描后做服务识别（协议 / 产品 / 版本 / WEB 指纹） |
| `-rules` | `data/fingerprint` | 规则路径：**逗号分隔列表，每项可为目录或 `.json` 文件**。目录保持 glob 行为；文件按文件名归类——含 `web_fingerprint` 进 Web 规则集，含 `service_fingerprint` 进 Service 规则集（单文件与 `partNN` 分片同等对待）。重复命中的文件只加载一次 |
| `-no-probes` | `false` | 只用被动探针，不发主动探针（等价 `Finger=tiny`） |
| `-out` | — | 结果 JSON 输出路径 |
| `-quiet` | `false` | 只输出汇总，不逐条打印 |
| `-reidentify` | — | 只重跑识别：读既有结果 JSON 的 `openPorts`，不重新扫描 |
| `-version` | — | 打印版本号 |

子命令：

| 命令 | 说明 |
| --- | --- |
| `rules-update [-rules 目录] [-ref main]` | 从 FingerprintHub 拉取最新规则并原子写入规则目录，详见下节 |

## 存活探测

`-alive` / `-alive-only` 用 **TCP connect 常用端口**判存活，任一端口连上即认定主机在线，并记录命中的端口。

不做 ICMP / raw socket：Windows 下 raw socket 需要管理员权限，且无权限时整条链路直接失效；TCP connect 无特权要求、跨平台行为一致，还顺带把「哪个端口开着」一起拿到。

- `-alive`：先探存活，再只对存活主机做完整端口扫描。大网段里死主机通常占多数，而 connect 扫描的耗时几乎全部来自死主机/过滤端口的超时，先筛存活能把总耗时压下来一个量级。日志形如 `[存活] 12/254 主机存活（1.8s）`，随后打印存活清单摘要。
- `-alive-only`：到此为止，只出活主机清单。`-out` JSON 里 `services` 为 `[]`，`openPorts` 填命中的存活端口，并附 `aliveHosts` 明细（`ip` + `openPorts`）、`aliveMode: true`、`aliveCount`。
- 已判定存活的主机，其剩余端口探测会提前结束（best-effort 短路），日志里的「短路跳过」即省下的探针数。
- 调优：`-alive-ports` 自定义探测端口（如只留 `22,80,443,445`），`-alive-timeout` 调超时（内网 `300`，跨网段 `800`）。
- 局限：过滤型防火墙可能丢弃非常用端口的 SYN，导致主机被误判为不存活。对准确性要求高的场景请直接用完整端口扫描（不加 `-alive`）。

## `rules-update` — 规则在线更新

```bash
cyberlook-scan rules-update [-rules data/fingerprint] [-ref main]
```

- 下载 `https://raw.githubusercontent.com/0x727/FingerprintHub/<ref>/web_fingerprint_v4.json` 与同目录的 `service_fingerprint_v4.json`。
- 标准库 `net/http`，**自动尊重环境 `http_proxy` / `https_proxy`**；单次超时 60s，失败重试 2 次（退避 2s、4s）。
- **原子写**：先落 `<name>.tmp` 并 `fsync`，再 `rename` 覆盖目标；下载或 JSON 校验失败时不改动原文件、不残留临时文件。
- service 更新后是**单文件**。仓库里的 `service_fingerprint_v4.partNN.json` 分片与新单文件共存会导致规则重复加载，因此成功后会删除旧分片——**删除前确认**新文件 JSON 可解析且条数 ≥ 旧分片总和，否则保留分片（宁可多加载也不丢规则）。
- 成功后逐文件打印字节数与规则条数；全部成功退出码 `0`，任一失败退出码 `1` 并打印失败 URL 与原因。
- `-rules` 给的是逗号列表时取第一项目录；给的是文件时写入该文件的父目录；目录不存在时创建。

> 注：GitHub raw 对大文件偶发连接重置，失败时重试或换 `ref` 即可。

## 规则数据

`data/fingerprint/` 内置 FingerprintHub 全量规则（MIT，见 `data/fingerprint/LICENSE.md`）：

| 文件 | 内容 |
| --- | --- |
| `web_fingerprint_v4.json` | web 指纹 3450 条（word 3081 / regex 503 / favicon 286），被动匹配 |
| `service_fingerprint_v4.part00-04.json` | service 探针 11938 条，分 5 片（单文件 9.4MB 走代理推 GitHub 易断） |

`Load` 同时兼容单文件与 `partNN` 分片共存，规则更新后无缝切换。

## 输出结构

```jsonc
{
  "targets": 254, "ports": 100, "probes": 25400,
  "open": 42, "closed": 24980, "filtered": 378, "errors": 0,
  "elapsedSec": 3.21, "pps": 7912.5,
  "aliveHosts": [{ "ip": "10.24.20.7", "openPorts": [22, 445] }],  // 启用 -alive* 时
  "aliveCount": 12,
  "openPorts": ["10.24.20.7:22"],
  "services": [{ "ip": "...", "port": 80, "protocol": "http", "product": "nginx",
                 "version": "1.20.1", "source": "probe", "score": 20 }],
  "protoStat": { "http": 30, "msrp": 12 },
  "productTop": { "nginx": 8 }
}
```

`-alive-only` 模式下 `services` 恒为 `[]`，`aliveMode: true`。

## License

GPL-3.0（见 `LICENSE`）。内置规则数据为 0x727/FingerprintHub，MIT（见 `data/fingerprint/LICENSE.md` 与 `THIRD_PARTY_NOTICES.md`）。

## 免责声明

仅用于授权范围内的安全测试与资产梳理。扫描他人网络可能造成服务干扰并可能违法，使用者自行承担全部责任。
