// cyberlook-scan — 自研端口扫描 + 全量指纹识别引擎（替代 TscanPlus）
//
// 用法示例：
//
//	cyberlook-scan -targets 10.24.20.0/24 -ports top100 -identify
//	cyberlook-scan -targets 10.24.20.0/24 -ports top100 -alive -identify
//	cyberlook-scan -targets 10.24.2.65,10.24.8.84 -ports 1-65535 -concurrency 1500
//	cyberlook-scan -reidentify result.json -rules data/fingerprint
//	cyberlook-scan rules-update -rules data/fingerprint -ref main
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RongSec/CyberLook-Scan/portscan"
	"github.com/RongSec/CyberLook-Scan/svcid"
)

const version = "1.4.2"

const banner = `
   ____                          __  __
  / ___|_   _  ___ _   _ _ __   |  \/  | __ _ _ __   __ _  ___ _ __
 | |   | | | |/ __| | | | '__|  | |\/| |/ _' | '_ \ / _' |/ _ \ '__|
 | |___| |_| | (__| |_| | |     | |  | | (_| | | | | (_| |  __/ |
  \____|\__, |\___|\__,_|_|     |_|  |_|\__,_|_| |_|\__, |\___|_|
        |___/                                       |___/

  自研端口扫描 + 全量指纹识别引擎  v` + version + `
  connect 扫描 · FingerprintHub 15388 条规则 · GPL-3.0
`

const usage = `用法:
  cyberlook-scan [选项]

目标与端口（scan 模式）:
  -targets string     目标：IP / CIDR / 区间 / 逗号分隔（也可用 @file 从文件读取）
  -ports string        端口：top100 / top1000 / 1-65535 / 22,80,443 / 混合（默认 top100）
  -exclude string      排除目标（同 -targets 语法）

扫描参数:
  -concurrency int     并发连接数（默认 1500）
  -timeout int         单端口超时毫秒（<100 视为秒，默认 1500）

存活探测:
  -alive               扫描前先做 TCP connect 存活探测，只对存活主机做端口扫描
  -alive-only          只探存活：输出活主机清单，不做端口扫描、不做识别（优先级高于 -alive）
  -alive-ports string  存活探测端口，逗号/区间语法（默认 80,443,22,445,3389,8080,8443,135,139,3306）
  -alive-timeout int   存活探测单端口超时毫秒（默认 400）

识别参数:
  -identify            扫描后做服务识别（协议/产品/版本/WEB 指纹）
  -rules string        FingerprintHub 规则路径，逗号分隔，每项可为目录或 .json 文件
                       （默认 data/fingerprint；文件名含 web_fingerprint/service_fingerprint 决定归属）
  -no-probes           只用被动探针，不发主动探针（等价 Finger=tiny）

输出:
  -out string          结果 JSON 输出路径
  -quiet               只输出汇总，不逐条打印

其他:
  -reidentify string   只重跑识别：读取既有结果 JSON 的 openPorts，不重新扫描
  -version             打印版本号
  -h, -help            显示本帮助

子命令:
  rules-update         从 FingerprintHub 拉取最新规则并原子写入规则目录
    cyberlook-scan rules-update [-rules 目录] [-ref main]

示例:
  # Top100 端口扫描 + 识别
  cyberlook-scan -targets 10.24.20.0/24 -ports top100 -identify

  # 先存活探测，再对活主机做全端口扫描 + 识别
  cyberlook-scan -targets 10.24.20.0/24 -ports top100 -alive -identify

  # 只看哪些主机活着
  cyberlook-scan -targets 10.24.20.0/24 -alive-only -out alive.json

  # 全端口扫描，只出结果不识别
  cyberlook-scan -targets 10.24.2.65 -ports 1-65535 -concurrency 2000

  # 自定义端口 + 输出 JSON
  cyberlook-scan -targets 10.24.2.65,10.24.8.84 -ports 22,80,443,3306 -identify -out result.json

  # 复用扫描结果，只重跑识别
  cyberlook-scan -reidentify result.json -rules data/fingerprint -out result2.json

  # 只指向单个规则文件
  cyberlook-scan -targets 10.24.2.65 -identify -rules /path/to/web_fingerprint_v4.json

  # 更新规则到最新版
  cyberlook-scan rules-update -rules data/fingerprint
`

type benchOut struct {
	Rules        map[string]int       `json:"rules,omitempty"`
	RulesLoadMs  int64                `json:"rulesLoadMs,omitempty"`
	AliveMode    bool                 `json:"aliveMode,omitempty"`  // true = -alive-only 纯存活探测结果
	AliveHosts   []portscan.AliveHost `json:"aliveHosts"`           // 存活主机清单（-alive / -alive-only；未启用时 []）
	AliveCount   int                  `json:"aliveCount,omitempty"` // 存活主机数
	Targets      int                  `json:"targets"`
	Ports        int                  `json:"ports"`
	Probes       int64                `json:"probes"`
	Open         int64                `json:"open"`
	Closed       int64                `json:"closed"`
	Filtered     int64                `json:"filtered"`
	Errors       int64                `json:"errors"`
	ElapsedSec   float64              `json:"elapsedSec"`
	PPS          float64              `json:"pps"`
	OpenPorts    []string             `json:"openPorts"`
	Services     []svcid.Service      `json:"services"`
	ProtoStat    map[string]int       `json:"protoStat,omitempty"`
	ProductTop   map[string]int       `json:"productTop,omitempty"`
	WithProduct  int                  `json:"withProduct"`
	WithVersion  int                  `json:"withVersion"`
	WithEvidence int                  `json:"withEvidence"`
	IdentSec     float64              `json:"identSec,omitempty"`
}

// normalize 保证序列化为数组的字段不会是 null（平台 ingest 按数组解析）
func (o *benchOut) normalize() {
	if o.OpenPorts == nil {
		o.OpenPorts = []string{}
	}
	if o.Services == nil {
		o.Services = []svcid.Service{}
	}
	if o.AliveHosts == nil {
		o.AliveHosts = []portscan.AliveHost{}
	}
}

func main() {
	targetsArg := flag.String("targets", "", "目标：IP / CIDR / 区间 / 逗号分隔 / @file")
	portsSpec := flag.String("ports", "top100", "端口表达式")
	exclude := flag.String("exclude", "", "排除目标")
	conc := flag.Int("concurrency", 1500, "并发连接数")
	timeoutMs := flag.Int("timeout", 1500, "单端口超时毫秒")
	alive := flag.Bool("alive", false, "扫描前先存活探测，只对存活主机端口扫描")
	aliveOnly := flag.Bool("alive-only", false, "只探存活，输出活主机清单（优先于 -alive）")
	alivePortsSpec := flag.String("alive-ports", "", "存活探测端口（默认 80,443,22,445,3389,8080,8443,135,139,3306）")
	aliveTimeoutMs := flag.Int("alive-timeout", 400, "存活探测单端口超时毫秒")
	doIdent := flag.Bool("identify", false, "扫描后做服务识别")
	rulesDir := flag.String("rules", "data/fingerprint", "规则路径：逗号分隔的目录或 .json 文件")
	noProbes := flag.Bool("no-probes", false, "不做主动探针")
	outPath := flag.String("out", "", "结果 JSON 输出路径")
	quiet := flag.Bool("quiet", false, "只输出汇总")
	reident := flag.String("reidentify", "", "只重跑识别")
	showVersion := flag.Bool("version", false, "版本号")

	flag.Usage = func() {
		fmt.Print(banner)
		fmt.Print(usage)
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("cyberlook-scan %s\n", version)
		return
	}
	// 无参数时显示帮助（含横幅）
	if len(os.Args) == 1 {
		flag.Usage()
		return
	}

	// ===== 子命令：rules-update =====
	if flag.Arg(0) == "rules-update" {
		// 外层已解析的 -rules 作为默认值，兼容 `rules-update -rules x` 与 `-rules x rules-update`
		os.Exit(runRulesUpdate(flag.Args()[1:], *rulesDir))
	}

	// ===== 只重跑识别 =====
	if *reident != "" {
		runReidentify(*reident, *rulesDir, *outPath, *conc, *quiet)
		return
	}

	// ===== 扫描 =====
	targets := loadTargets(*targetsArg, *exclude)
	if len(targets) == 0 {
		fmt.Println("[错误] 没有目标，用 -targets 指定（IP / CIDR / 区间 / @file）")
		os.Exit(1)
	}
	// -alive-only 优先于 -alive：纯存活探测不做端口扫描与识别
	aliveMode := *aliveOnly || *alive
	aliveOnlyMode := *aliveOnly
	ports := []int(nil)
	var err error
	if !aliveOnlyMode {
		ports, err = portscan.ParsePorts(*portsSpec)
		if err != nil {
			fmt.Println("[错误] 端口解析失败:", err)
			os.Exit(1)
		}
	}

	timeout := time.Duration(*timeoutMs) * time.Millisecond
	if *timeoutMs > 0 && *timeoutMs < 100 {
		timeout = time.Duration(*timeoutMs) * time.Second
	}
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	fmt.Print(banner)

	ctx := context.Background()

	// ===== 存活探测（TCP connect 常用端口，任一命中即判存活） =====
	var aliveHosts []portscan.AliveHost
	totalTargets := len(targets)
	if aliveMode {
		var alivePorts []int
		var aerr error
		alivePorts, aerr = parseAlivePorts(*alivePortsSpec)
		if aerr != nil {
			fmt.Println("[错误] 存活探测端口解析失败:", aerr)
			os.Exit(1)
		}
		aliveTimeout := time.Duration(*aliveTimeoutMs) * time.Millisecond
		if aliveTimeout <= 0 {
			aliveTimeout = portscan.DefaultAliveTimeout
		}
		fmt.Printf("[存活] 探测 %d 个主机 × %d 个常用端口 %v，并发 %d，超时 %s\n",
			len(targets), len(alivePorts), alivePorts, *conc, aliveTimeout)
		hosts, ast := portscan.AliveProbeStats(ctx, targets, alivePorts, *conc, aliveTimeout)
		aliveHosts = hosts
		fmt.Printf("[存活] %d/%d 主机存活（%.1fs，探针 %d，短路跳过 %d）\n",
			ast.Alive, ast.Hosts, ast.Elapsed.Seconds(), ast.Probes, ast.Skipped)
		printAliveSummary(hosts)

		if aliveOnlyMode {
			out := benchOut{
				AliveMode:  true,
				AliveHosts: aliveHosts,
				AliveCount: len(aliveHosts),
				Targets:    ast.Hosts,
				Ports:      ast.Ports,
				Probes:     ast.Probes,
				ElapsedSec: ast.Elapsed.Seconds(),
				PPS:        alivePPS(ast),
				Services:   []svcid.Service{},
			}
			for _, h := range aliveHosts {
				for _, p := range h.OpenPorts {
					out.OpenPorts = append(out.OpenPorts, fmt.Sprintf("%s:%d", h.IP, p))
				}
			}
			out.Open = int64(len(out.OpenPorts)) // 存活模式下 open = 命中的存活端口数
			fmt.Printf("\n===== 存活清单（%d 台）=====\n", len(aliveHosts))
			if !*quiet {
				for _, h := range aliveHosts {
					fmt.Printf("  %-18s %v\n", h.IP, h.OpenPorts)
				}
			}
			if *outPath != "" {
				out.normalize()
				if b, e := json.MarshalIndent(out, "", "  "); e == nil {
					_ = os.WriteFile(*outPath, b, 0o644)
					fmt.Printf("\n结果已写入 %s\n", *outPath)
				}
			}
			return
		}

		// 只对存活主机做端口扫描
		var live []string
		for _, h := range aliveHosts {
			live = append(live, h.IP)
		}
		targets = live
		if len(targets) == 0 {
			fmt.Println("[存活] 没有存活主机，跳过端口扫描")
			if *outPath != "" {
				empty := benchOut{Targets: totalTargets, Ports: len(ports), OpenPorts: []string{}, Services: []svcid.Service{}, AliveHosts: []portscan.AliveHost{}}
				b, _ := json.MarshalIndent(empty, "", "  ")
				_ = os.WriteFile(*outPath, b, 0o644)
				fmt.Printf("结果已写入 %s\n", *outPath)
			}
			return
		}
	}

	fmt.Printf("[扫描] 目标 %d 个 × 端口 %d 个 = %d 探针，并发 %d，超时 %s\n",
		len(targets), len(ports), len(targets)*len(ports), *conc, timeout)

	// 规则
	var rs *svcid.RuleSet
	var probes *svcid.ProbeIndex
	loadStart := time.Now()
	if *doIdent {
		rs, err = svcid.Load(*rulesDir)
		if err != nil {
			fmt.Println("[警告] 规则加载失败，仅做端口扫描:", err)
		} else {
			probes = rs.BuildServiceProbes()
			fmt.Printf("[规则] 加载 %dms：%v\n", time.Since(loadStart).Milliseconds(), rs.Stats())
			if *noProbes {
				probes = nil
				fmt.Println("[规则] 已禁用主动探针（-no-probes）")
			}
		}
	}

	opens, st, err := portscan.Scan(ctx, targets, ports, portscan.Options{
		Concurrency: *conc,
		Timeout:     timeout,
		OnProgress: func(done, total, open int64) {
			if !*quiet {
				fmt.Printf("[进度] %d/%d（%.1f%%）开放 %d\n", done, total, float64(done)*100/float64(total), open)
			}
		},
	})
	if err != nil && errors.Is(err, portscan.ErrLocalResourceExhausted) {
		// 本机 fd/端口不足：结果不可信，必须非 0 退出，别让调用方当成"没有开放端口"
		fmt.Println("[错误] 本机 fd/端口资源不足，结果不可信（请调大 nofile 或调小并发）:", err)
		os.Exit(3)
	}
	if err != nil && len(opens) == 0 {
		fmt.Println("[错误] 扫描失败:", err)
		os.Exit(1)
	}

	out := benchOut{
		Targets: totalTargets, Ports: len(ports),
		Probes: st.Probes, Open: st.Open, Closed: st.Closed, Filtered: st.Filtered, Errors: st.Errors,
		ElapsedSec: st.Elapsed.Seconds(), PPS: st.PPS(), RulesLoadMs: time.Since(loadStart).Milliseconds(),
		AliveHosts: aliveHosts,
	}
	if len(aliveHosts) > 0 {
		out.AliveCount = len(aliveHosts)
	}
	if rs != nil {
		out.Rules = rs.Stats()
	}
	for _, r := range opens {
		out.OpenPorts = append(out.OpenPorts, fmt.Sprintf("%s:%d", r.IP, r.Port))
	}

	fmt.Printf("\n===== 扫描结果 =====\n")
	if aliveMode {
		fmt.Printf("主机：%d/%d 存活（已只对存活主机做端口扫描）\n", len(aliveHosts), totalTargets)
	}
	fmt.Printf("探针 %d，用时 %s，速率 %.0f 探针/秒\n", st.Probes, st.Elapsed.Round(time.Second), st.PPS())
	fmt.Printf("开放 %d，关闭 %d（RST），过滤/超时 %d，错误 %d\n", st.Open, st.Closed, st.Filtered, st.Errors)
	if st.LocalResErrs > 0 {
		// 本地 fd/端口不够导致的未发探针：结果可能不完整，必须显式告警
		fmt.Printf("⚠️ 本地 fd/端口不足 %d 次（结果可能漏报，请调大 nofile 或调小并发）\n", st.LocalResErrs)
	}
	if !*quiet {
		fmt.Printf("开放端口：%v\n", out.OpenPorts)
	}

	// 识别
	if rs != nil && len(opens) > 0 {
		ti := time.Now()
		out.Services = make([]svcid.Service, 0, len(opens))
		out.ProtoStat = map[string]int{}
		out.ProductTop = map[string]int{}
		var mu sync.Mutex
		sem := make(chan struct{}, max(8, *conc/32))
		var wg sync.WaitGroup
		for _, r := range opens {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-sem }()
				sv := svcid.Identify(ctx, ip, port, svcid.IdentOptions{Rules: rs, Probes: probes})
				mu.Lock()
				out.Services = append(out.Services, sv)
				out.ProtoStat[sv.Protocol]++
				if sv.Product != "" {
					out.ProductTop[sv.Product]++
					out.WithProduct++
					if sv.Source != "port-hint" {
						out.WithEvidence++
					}
				}
				if sv.Version != "" {
					out.WithVersion++
				}
				mu.Unlock()
			}(r.IP, r.Port)
		}
		wg.Wait()
		out.IdentSec = time.Since(ti).Seconds()
		sort.Slice(out.Services, func(i, j int) bool {
			if out.Services[i].IP == out.Services[j].IP {
				return out.Services[i].Port < out.Services[j].Port
			}
			return out.Services[i].IP < out.Services[j].IP
		})

		fmt.Printf("\n===== 识别结果（%d 个开放端口，用时 %s）=====\n", len(out.Services), time.Since(ti).Round(time.Millisecond))
		fmt.Printf("有产品名 %d（%.0f%%），其中**有证据** %d（%.0f%%），有版本 %d（%.0f%%）\n",
			out.WithProduct, pctf(out.WithProduct, len(out.Services)),
			out.WithEvidence, pctf(out.WithEvidence, len(out.Services)),
			out.WithVersion, pctf(out.WithVersion, len(out.Services)))
		fmt.Printf("协议分布：%v\n", out.ProtoStat)
		printTop(out.ProductTop, 20)
	}

	if *outPath != "" {
		out.normalize()
		if b, e := json.MarshalIndent(out, "", "  "); e == nil {
			_ = os.WriteFile(*outPath, b, 0o644)
			fmt.Printf("\n结果已写入 %s\n", *outPath)
		}
	}
}

func runReidentify(src, rulesDir, outPath string, conc int, quiet bool) {
	fmt.Print(banner)
	b, err := os.ReadFile(src)
	if err != nil {
		fmt.Println("[错误] 读取失败:", err)
		os.Exit(1)
	}
	var old benchOut
	if err := json.Unmarshal(b, &old); err != nil {
		fmt.Println("[错误] 解析失败:", err)
		os.Exit(1)
	}
	rs, err := svcid.Load(rulesDir)
	if err != nil {
		fmt.Println("[错误] 规则加载失败:", err)
		os.Exit(1)
	}
	probes := rs.BuildServiceProbes()
	fmt.Printf("[规则] %v，主动探针端口组 %d\n", rs.Stats(), probes.PortCount())

	out := old
	out.AliveMode = false // 重跑识别后是完整结果，不再是纯存活清单
	out.Services = nil
	out.ProtoStat = map[string]int{}
	out.ProductTop = map[string]int{}
	out.WithProduct, out.WithVersion, out.WithEvidence = 0, 0, 0
	var mu sync.Mutex
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	ctx := context.Background()
	t0 := time.Now()
	for _, k := range old.OpenPorts {
		parts := strings.Split(k, ":")
		if len(parts) != 2 {
			continue
		}
		ip := parts[0]
		var port int
		_, _ = fmt.Sscanf(parts[1], "%d", &port)
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			sv := svcid.Identify(ctx, ip, port, svcid.IdentOptions{Rules: rs, Probes: probes})
			mu.Lock()
			out.Services = append(out.Services, sv)
			out.ProtoStat[sv.Protocol]++
			if sv.Product != "" {
				out.ProductTop[sv.Product]++
				out.WithProduct++
				if sv.Source != "port-hint" {
					out.WithEvidence++
				}
			}
			if sv.Version != "" {
				out.WithVersion++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	out.IdentSec = time.Since(t0).Seconds()
	fmt.Printf("[识别] %d 个端口，用时 %s，有产品 %d（%.0f%%），**有证据** %d（%.0f%%），有版本 %d（%.0f%%）\n",
		len(out.Services), time.Since(t0).Round(time.Millisecond), out.WithProduct,
		pctf(out.WithProduct, len(out.Services)), out.WithEvidence,
		pctf(out.WithEvidence, len(out.Services)), out.WithVersion, pctf(out.WithVersion, len(out.Services)))
	if !quiet {
		fmt.Printf("协议：%v\n", out.ProtoStat)
		printTop(out.ProductTop, 20)
	}
	if outPath != "" {
		out.normalize()
		if b, e := json.MarshalIndent(out, "", "  "); e == nil {
			_ = os.WriteFile(outPath, b, 0o644)
			fmt.Printf("已写入 %s\n", outPath)
		}
	}
}

// alivePPS 存活探测的探针速率（探针/秒）
func alivePPS(st portscan.AliveStats) float64 {
	if st.Elapsed <= 0 {
		return 0
	}
	return float64(st.Probes) / st.Elapsed.Seconds()
}

// parseAlivePorts 解析存活探测端口；空串回落到 portscan.DefaultAlivePorts
func parseAlivePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return append([]int(nil), portscan.DefaultAlivePorts...), nil
	}
	return portscan.ParsePorts(spec)
}

// printAliveSummary 打印存活清单摘要（最多 20 台，其余折叠为计数）
func printAliveSummary(hosts []portscan.AliveHost) {
	const maxShow = 20
	if len(hosts) == 0 {
		fmt.Println("[存活] 未发现存活主机")
		return
	}
	n := len(hosts)
	if n > maxShow {
		n = maxShow
	}
	fmt.Printf("[存活] 存活清单（前 %d 台）：", n)
	for i := 0; i < n; i++ {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Printf("%s%v", hosts[i].IP, hosts[i].OpenPorts)
	}
	if len(hosts) > maxShow {
		fmt.Printf(" …（其余 %d 台省略）", len(hosts)-maxShow)
	}
	fmt.Println()
}

// loadTargets 解析目标：@file / 逗号 / CIDR / 区间
func loadTargets(spec, exclude string) []string {
	var raw []string
	if strings.HasPrefix(spec, "@") {
		if b, err := os.ReadFile(spec[1:]); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					raw = append(raw, line)
				}
			}
		}
	} else {
		for _, t := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			if t = strings.TrimSpace(t); t != "" {
				raw = append(raw, t)
			}
		}
	}
	var ex []string
	if exclude != "" {
		for _, t := range strings.FieldsFunc(exclude, func(r rune) bool { return r == ',' || r == ' ' }) {
			if t = strings.TrimSpace(t); t != "" {
				ex = append(ex, t)
			}
		}
	}
	// 展开 CIDR / 区间
	seen := map[string]bool{}
	var out []string
	for _, t := range raw {
		for _, ip := range expandTarget(t) {
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	if len(ex) > 0 {
		exSet := map[string]bool{}
		for _, t := range ex {
			for _, ip := range expandTarget(t) {
				exSet[ip] = true
			}
		}
		var filtered []string
		for _, ip := range out {
			if !exSet[ip] {
				filtered = append(filtered, ip)
			}
		}
		out = filtered
	}
	return out
}

// expandTarget 展开单个目标（IP / CIDR / a.b.c.d-e / a.b.c.d-a.b.c.f）
func expandTarget(t string) []string {
	// 已是纯 IP
	if isIP(t) {
		return []string{t}
	}
	// CIDR
	if strings.Contains(t, "/") {
		return expandCIDR(t)
	}
	// 区间：10.24.20.1-20 或 10.24.20.1-10.24.20.20
	if i := strings.Index(t, "-"); i > 0 {
		left := strings.TrimSpace(t[:i])
		right := strings.TrimSpace(t[i+1:])
		if isIP(left) {
			if isIP(right) {
				return expandRange(left, right)
			}
			// 10.24.20.1-20
			if n, err := strconv.Atoi(right); err == nil {
				base := left[:strings.LastIndex(left, ".")+1]
				lo, _ := strconv.Atoi(left[strings.LastIndex(left, ".")+1:])
				var ips []string
				for x := lo; x <= n && x <= 255; x++ {
					ips = append(ips, fmt.Sprintf("%s%d", base, x))
				}
				return ips
			}
		}
	}
	return nil
}

func isIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func expandCIDR(cidr string) []string {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 || !isIP(parts[0]) {
		return nil
	}
	ones, err := strconv.Atoi(parts[1])
	if err != nil || ones < 0 || ones > 32 {
		return nil
	}
	base := ipToInt(parts[0])
	mask := uint32(0xFFFFFFFF) << (32 - ones)
	network := base & mask
	broadcast := network | ^mask
	var ips []string
	for x := network; x <= broadcast; x++ {
		// 跳过网络/广播地址（/31、/32 除外）
		if ones < 31 && (x == network || x == broadcast) {
			continue
		}
		ips = append(ips, intToIP(x))
	}
	return ips
}

func expandRange(a, b string) []string {
	lo, hi := ipToInt(a), ipToInt(b)
	if lo > hi {
		lo, hi = hi, lo
	}
	var ips []string
	for x := lo; x <= hi; x++ {
		ips = append(ips, intToIP(x))
	}
	return ips
}

func ipToInt(s string) uint32 {
	parts := strings.Split(s, ".")
	var v uint32
	for _, p := range parts {
		n, _ := strconv.Atoi(p)
		v = v<<8 | uint32(n)
	}
	return v
}

func intToIP(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", v>>24, (v>>16)&0xFF, (v>>8)&0xFF, v&0xFF)
}

func printTop(m map[string]int, n int) {
	type kv struct {
		K string
		V int
	}
	var tops []kv
	for k, v := range m {
		tops = append(tops, kv{k, v})
	}
	sort.Slice(tops, func(i, j int) bool { return tops[i].V > tops[j].V })
	fmt.Println("产品 Top：")
	for i, t := range tops {
		if i >= n {
			break
		}
		fmt.Printf("  %-40s %d\n", t.K, t.V)
	}
}

func pctf(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
