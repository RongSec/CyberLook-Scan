package main

// rules-update 子命令：从 0x727/FingerprintHub 拉取最新规则并原子写入本地规则目录。
//
// 设计要点：
//   - 只用标准库 net/http，默认 Transport 自动尊重 http_proxy / https_proxy 环境变量；
//     单次超时 60s，失败重试 2 次（共 3 次尝试）。
//   - 原子写：先写 <name>.tmp（同目录，保证同一文件系统），fsync 后 rename 覆盖目标；
//     中途失败不会破坏既有规则文件。
//   - service 规则更新后落地为**单文件**，与仓库里的 partNN 分片共存会导致规则重复加载，
//     因此写成功后要删除旧分片——但删除前必须确认新单文件 JSON 可解析且条数 ≥ 旧分片总和，
//     否则保留分片（宁可多加载也不丢规则）。

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// fingerprintHubRawBase FingerprintHub raw 根地址（包级变量便于测试注入本地服务）
var fingerprintHubRawBase = "https://raw.githubusercontent.com/0x727/FingerprintHub"

// 每个规则文件的下载规格
type ruleFileSpec struct {
	name    string // 落地文件名
	urlPath string // raw URL 相对路径
	kind    string // web / service（用于条数解析）
	pattern string // 旧分片文件匹配（service 用）
	shardRe *regexp.Regexp
}

// downloadTimeout 单次 HTTP 请求超时；downloadRetries 额外重试次数
const (
	downloadTimeout = 60 * time.Second
	downloadRetries = 2
)

// retryBackoffBase 重试退避基数（第 n 次重试等待 n*base）；包级变量便于测试缩短
var retryBackoffBase = 2 * time.Second

// runRulesUpdate 执行 rules-update 子命令，返回进程退出码（0 成功 / 1 失败）。
// defaultRules 是主 flag 集里解析到的 -rules 值（子命令未显式给 -rules 时沿用它）。
func runRulesUpdate(args []string, defaultRules string) int {
	fs := flag.NewFlagSet("rules-update", flag.ContinueOnError)
	rulesPath := fs.String("rules", "", "规则目录（写入目标；-rules 列表里多路径时取第一项；缺省沿用全局 -rules）")
	ref := fs.String("ref", "main", "FingerprintHub 分支/ref")
	fs.Usage = func() {
		fmt.Print(banner)
		fmt.Print(usage)
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}
	rules := strings.TrimSpace(*rulesPath)
	if rules == "" {
		rules = defaultRules
	}

	dir, err := resolveRuleDir(rules)
	if err != nil {
		fmt.Println("[错误]", err)
		return 1
	}

	specs := []ruleFileSpec{
		{
			name:    "web_fingerprint_v4.json",
			urlPath: "web_fingerprint_v4.json",
			kind:    "web",
			pattern: "web_fingerprint_v4*.json",
		},
		{
			name:    "service_fingerprint_v4.json",
			urlPath: "service_fingerprint_v4.json",
			kind:    "service",
			pattern: "service_fingerprint_v4.part*.json",
			shardRe: regexp.MustCompile(`^service_fingerprint_v4\.part\d+\.json$`),
		},
	}

	fmt.Printf("[更新] 目标目录 %s，来源 %s/%s\n", dir, fingerprintHubRawBase, *ref)

	var failed int
	for _, sp := range specs {
		url := fingerprintHubRawBase + "/" + *ref + "/" + sp.urlPath
		fmt.Printf("[下载] %s\n", url)
		body, err := httpGetWithRetry(url)
		if err != nil {
			fmt.Printf("[失败] %s\n  URL: %s\n  原因: %v\n", sp.name, url, err)
			failed++
			continue
		}
		// 先校验 JSON 合法性与条数，再落盘（避免把坏文件写进去）
		newCount, err := countRules(sp.kind, body)
		if err != nil {
			fmt.Printf("[失败] %s 返回内容不是合法规则 JSON：%v\n  URL: %s\n", sp.name, err, url)
			failed++
			continue
		}
		finalPath := filepath.Join(dir, sp.name)
		oldCount, oldShards := shardRuleCount(dir, sp)
		tmpPath := finalPath + ".tmp"
		if err := atomicWrite(tmpPath, finalPath, body); err != nil {
			fmt.Printf("[失败] 写入 %s: %v\n", finalPath, err)
			failed++
			continue
		}
		fi, _ := os.Stat(finalPath)
		var size int64
		if fi != nil {
			size = fi.Size()
		}
		fmt.Printf("[完成] %s：%d 字节，%d 条规则\n", sp.name, size, newCount)

		// service 单文件落地后清理旧分片，避免重复加载
		if oldShards > 0 {
			if oldCount < 0 {
				fmt.Printf("[保留] 检测到 %d 个旧分片但无法统计条数，保守**不删除分片**\n", oldShards)
				continue
			}
			if newCount < oldCount {
				fmt.Printf("[保留] 检测到 %d 个旧分片共 %d 条，新单文件仅 %d 条，为不丢规则**不删除分片**\n",
					oldShards, oldCount, newCount)
				continue
			}
			var removed int
			for _, f := range listShards(dir, sp) {
				if err := os.Remove(f); err != nil {
					fmt.Printf("[警告] 删除分片失败 %s: %v\n", filepath.Base(f), err)
					continue
				}
				removed++
			}
			fmt.Printf("[清理] 已删除 %d 个旧分片（合计 %d 条，已被新单文件 %d 条覆盖）\n", removed, oldCount, newCount)
		}
	}

	if failed > 0 {
		fmt.Printf("[结果] %d 个文件更新失败（可检查网络/代理 http_proxy 后重试）\n", failed)
		return 1
	}
	fmt.Println("[结果] 规则更新完成")
	return 0
}

// resolveRuleDir 把 -rules 值解析成可写的规则目录：
// 逗号列表取第一项；第一项是文件时用其父目录；目录不存在时创建。
func resolveRuleDir(paths string) (string, error) {
	first := ""
	for _, p := range strings.Split(paths, ",") {
		if p = strings.TrimSpace(p); p != "" {
			first = p
			break
		}
	}
	if first == "" {
		return "", fmt.Errorf("-rules 不能为空")
	}
	fi, err := os.Stat(first)
	if err == nil && !fi.IsDir() {
		first = filepath.Dir(first)
	}
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("规则路径 %s 不可用: %w", first, err)
	}
	if err := os.MkdirAll(first, 0o755); err != nil {
		return "", fmt.Errorf("创建规则目录 %s: %w", first, err)
	}
	return first, nil
}

// httpGetWithRetry 下载 URL，尊重环境代理，单次超时 60s，失败重试 2 次。
func httpGetWithRetry(url string) ([]byte, error) {
	client := &http.Client{
		Timeout:   downloadTimeout,
		Transport: &http.Transport{}, // 空 Transport = 使用环境 HTTP_PROXY/HTTPS_PROXY（ProxyFromEnvironment）
	}
	var lastErr error
	for attempt := 0; attempt <= downloadRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt) * retryBackoffBase
			fmt.Printf("[重试] 第 %d 次尝试，等待 %s\n", attempt, backoff)
			time.Sleep(backoff)
		}
		body, err := httpOnce(client, url)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func httpOnce(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cyberlook-scan/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, fmt.Errorf("读取响应体: %w", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("响应体为空")
	}
	return body, nil
}

// countRules 解析规则 JSON 并返回条数，同时校验是否为数组结构
func countRules(kind string, b []byte) (int, error) {
	if kind == "web" {
		var v []WebRuleShim
		if err := json.Unmarshal(b, &v); err != nil {
			// 兼容上游把 web 规则改成对象包装的情况
			return 0, err
		}
		return len(v), nil
	}
	var v []SvcRuleShim
	if err := json.Unmarshal(b, &v); err != nil {
		return 0, err
	}
	return len(v), nil
}

// WebRuleShim / SvcRuleShim 仅用于统计条数的最小结构（不复用 svcid 类型，避免为此引入编译依赖）
type WebRuleShim struct {
	ID   string `json:"id"`
	Info struct {
		Name string `json:"name"`
	} `json:"info"`
}

type SvcRuleShim struct {
	ID   string `json:"id"`
	Info struct {
		Name string `json:"name"`
	} `json:"info"`
}

// listShards 返回目录下该规则的旧分片文件（升序）
func listShards(dir string, sp ruleFileSpec) []string {
	if sp.shardRe == nil {
		return nil
	}
	m, _ := filepath.Glob(filepath.Join(dir, sp.pattern))
	sort.Strings(m)
	var out []string
	for _, f := range m {
		if sp.shardRe.MatchString(filepath.Base(f)) && filepath.Base(f) != sp.name {
			out = append(out, f)
		}
	}
	return out
}

// shardRuleCount 统计旧分片的文件数与规则总条数（用于删除前 safety check）
func shardRuleCount(dir string, sp ruleFileSpec) (count int, files int) {
	shards := listShards(dir, sp)
	if len(shards) == 0 {
		return 0, 0
	}
	kind := sp.kind
	for _, f := range shards {
		b, err := os.ReadFile(f)
		if err != nil {
			// 读不到分片时按"条数未知且非零"处理，保守不删
			return -1, len(shards)
		}
		n, err := countRules(kind, b)
		if err != nil {
			return -1, len(shards)
		}
		count += n
	}
	return count, len(shards)
}

// atomicWrite 先写 tmp 再 rename 覆盖目标，保证读者永远只能看到完整文件。
func atomicWrite(tmpPath, finalPath string, data []byte) error {
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("创建临时文件: %w", err)
	}
	writeOK := false
	defer func() {
		_ = f.Close()
		if !writeOK {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("写入: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("落盘: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("关闭: %w", err)
	}
	// Windows 上 rename 不能覆盖已存在文件，先移除目标（此刻新文件已完整落盘，风险窗口极小）
	if _, err := os.Stat(finalPath); err == nil {
		if err := os.Remove(finalPath); err != nil {
			return fmt.Errorf("替换目标: %w", err)
		}
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("重命名: %w", err)
	}
	writeOK = true
	return nil
}
