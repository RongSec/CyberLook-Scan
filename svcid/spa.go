package svcid

// SPA 兜底取证。
//
// 背景：越来越多的设备和系统前端是「空壳页面 + JS 渲染」，HTML 里只有一个
// <div id="app"> 和几个 script 标签，<title> 甚至留空，产品名由 JS 在运行时
// 从后端接口取回来再写进 DOM。此时纯静态匹配拿不到任何东西，于是出现两类错：
//
//	① 识别不出来（浏览器打开明明写着"大模型安全护栏"）
//	② 用页面里残留的通用词误判（例如 portal/login 命中某条只沾一个词的规则）
//
// 本文件补的正是这一段：按 <base href> 正确定位 JS（相对路径常常是
// /static/ 而不是站点根，拼错就是 401），从 JS 里抽出同源只读接口，
// 取回 JSON 里的产品名/介绍/版权等字段，作为"补语料"交给规则再匹配一次，
// 同时把产品名回填成 title（即便没有规则命中，也能落到 http-title 兜底）。
//
// 边界很硬：只 GET、只同源、只读白名单接口、有字节与次数上限。
// 目的是"看清它自己声明的身份"，不是做爬虫。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const (
	spaMaxHTML     = 32 << 10 // 超过 32KB 的页面不按空壳 SPA 处理（说明内容已在 HTML 里）
	spaMaxJSFiles  = 2
	spaMaxJSBytes  = 1 << 20 // 单个 JS 最多读 1MB
	spaMaxAPICalls = 4
	spaMaxAPIBytes = 64 << 10
	spaCorpusLimit = 6 << 10
)

var (
	reBaseHref  = regexp.MustCompile(`(?is)<base[^>]+href\s*=\s*["']([^"']+)["']`)
	reScriptSrc = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	reAppRoot   = regexp.MustCompile(`(?is)<(?:div|main|section)[^>]+id\s*=\s*["'](?:app|root|__next|__nuxt)["']|ng-app\s*=`)
	// JS 里的路径字面量："/api/xxx"、'/ngsoc/AUTH/api/v3/login'
	reAPIPath = regexp.MustCompile("[\"'`](/[A-Za-z0-9_\\-./]{2,120})[\"'`]")
	// document.title = "..."（有些系统只在 JS 里写死标题）
	reDocTitle = regexp.MustCompile(`(?is)document\.title\s*=\s*["']([^"']{2,120})["']`)
)

// 值得 GET 的"只读信息类"接口（小写子串匹配）
var spaAPINeedles = []string{
	"loginpage", "customize", "portal", "status", "version", "config",
	"info", "public", "about", "health", "meta",
}

// 会改状态或涉及凭据的路径一律跳过（即便出现在白名单关键词里）
var spaAPIDeny = []string{
	"logout", "signout", "password", "passwd", "captcha", "verifycode",
	"pubkey", "token", "refresh", "sms", "send", "upload", "delete",
	"remove", "save", "update", "create", "reset", "login",
}

// 产品名/介绍类 JSON 字段（小写 key 精确匹配）
var spaKeyWhitelist = map[string]bool{
	"platformname":        true,
	"platformintroduction": true,
	"platform":            true,
	"productname":         true,
	"product":             true,
	"sysname":             true,
	"systemname":          true,
	"logotext":            true,
	"navtext":             true,
	"logintext":           true,
	"title":               true,
	"description":         true,
	"copyright":           true,
	"footer":              true,
}

type spaResult struct {
	Corpus  string   // 补语料（供规则二次匹配）
	Title   string   // 产品名/标题（即使规则没命中，也走 http-title 兜底）
	APIHits []string // 证据描述
	JSNum   int
}

// looksLikeSPA 判断是否是"空壳 SPA"：内容少 + 有外链脚本 + 有应用挂载点或空标题
func looksLikeSPA(html string) bool {
	if html == "" || len(html) > spaMaxHTML {
		return false
	}
	hasScript := strings.Contains(strings.ToLower(html), "<script") && reScriptSrc.MatchString(html)
	if !hasScript {
		return false
	}
	hasRoot := reAppRoot.MatchString(html)
	emptyTitle := strings.TrimSpace(extractTitle(html)) == ""
	return hasRoot || emptyTitle
}

// spaEnrich 对空壳 SPA 做一次取证。
// jsTimeout 是单个请求的超时；函数总耗时受 ctx 约束。
func spaEnrich(ctx context.Context, cl *http.Client, pageURL, html string, jsTimeout int) spaResult {
	var out spaResult
	if !looksLikeSPA(html) {
		return out
	}
	base, err := url.Parse(pageURL)
	if err != nil {
		return out
	}

	// ── 1) 抓同源 JS ──
	jsTexts := fetchSPAScripts(ctx, cl, base, html, jsTimeout)
	out.JSNum = len(jsTexts)

	jsAll := strings.Join(jsTexts, "\n")

	// ── 2) 抽同源只读接口 ──
	paths := pickSPAPaths(html+"\n"+jsAll)
	var parts []string
	for _, p := range paths {
		body, ok := spaGET(ctx, cl, base, p, jsTimeout)
		if !ok {
			continue
		}
		kvs := flattenJSONStrings(body)
		if len(kvs) == 0 {
			continue
		}
		var seg []string
		for _, kv := range kvs {
			seg = append(seg, kv)
			if out.Title == "" && spaKeyWhitelist[strings.ToLower(kvKey(kv))] {
				// 由下面的 platformName 优先逻辑统一处理，这里只兜底
				_ = kv
			}
		}
		if name := spaJSONProductName(body); name != "" && out.Title == "" {
			out.Title = name
		}
		joined := strings.Join(seg, " | ")
		parts = append(parts, joined)
		out.APIHits = append(out.APIHits, "spa-api:"+p+" → "+truncRunes(joined, 160))
	}

	// ── 3) JS 里写死的标题（document.title = "..."）──
	if out.Title == "" {
		if m := reDocTitle.FindStringSubmatch(jsAll); len(m) > 1 {
			out.Title = strings.TrimSpace(m[1])
		}
	}
	// ── 4) 补语料：接口字段 + JS 里的标题 ──
	if out.Title != "" {
		parts = append(parts, "spa-title:"+out.Title)
	}
	corpus := strings.Join(parts, "\n")
	if len(corpus) > spaCorpusLimit {
		corpus = corpus[:spaCorpusLimit]
	}
	out.Corpus = corpus
	return out
}

// fetchSPAScripts 按 <base href> 解析 script src，抓同源的前 N 个。
// 优先 bootstrap/main/app/index 这类入口包，把 vendor 大包排后面——
// 产品名通常在入口包里，vendor 只有框架。
func fetchSPAScripts(ctx context.Context, cl *http.Client, base *url.URL, html string, timeout int) []string {
	baseHref := ""
	if m := reBaseHref.FindStringSubmatch(html); len(m) > 1 {
		baseHref = strings.TrimSpace(m[1])
	}
	root := *base
	root.RawQuery, root.Fragment = "", ""
	if baseHref != "" {
		if b, err := root.Parse(baseHref); err == nil {
			root = *b
		}
	}

	type cand struct {
		u    string
		rank int
	}
	var cands []cand
	seen := map[string]bool{}
	for _, m := range reScriptSrc.FindAllStringSubmatch(html, -1) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(strings.ToLower(raw), "data:") {
			continue
		}
		abs, err := root.Parse(raw)
		if err != nil || abs.Host != base.Host {
			continue // 只跟同源，避免把 CDN 上的通用库当成特征
		}
		u := abs.String()
		if seen[u] {
			continue
		}
		seen[u] = true
		low := strings.ToLower(u)
		rank := 5
		for _, kw := range []string{"bootstrap", "main.", "app.", "index.", "entry", "login"} {
			if strings.Contains(low, kw) {
				rank = 0
				break
			}
		}
		if strings.Contains(low, "vendor") || strings.Contains(low, "chunk-vendors") {
			rank = 9
		}
		cands = append(cands, cand{u: u, rank: rank})
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].rank < cands[j].rank })

	var texts []string
	for _, c := range cands {
		if len(texts) >= spaMaxJSFiles {
			break
		}
		req, err := http.NewRequestWithContext(ctx, "GET", c.u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0")
		resp, err := cl.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, spaMaxJSBytes))
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || len(b) < 256 {
			continue // 401/403 说明资源受保护，别浪费预算
		}
		texts = append(texts, string(b))
	}
	return texts
}

// pickSPAPaths 从 JS/HTML 里挑出"只读信息类"同源接口，最多 spaMaxAPICalls 个。
func pickSPAPaths(src string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reAPIPath.FindAllStringSubmatch(src, -1) {
		p := strings.TrimSpace(m[1])
		if p == "" || seen[p] || strings.Contains(p, "..") {
			continue
		}
		low := strings.ToLower(p)
		if !strings.Contains(low, "api") && !strings.Contains(low, "rest") {
			continue
		}
		denied := false
		for _, d := range spaAPIDeny {
			if strings.Contains(low, d) && !strings.Contains(low, "loginpage") {
				denied = true
				break
			}
		}
		if denied {
			continue
		}
		worth := false
		for _, n := range spaAPINeedles {
			if strings.Contains(low, n) {
				worth = true
				break
			}
		}
		if !worth {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) >= spaMaxAPICalls {
			break
		}
	}
	return out
}

// spaGET 同源 GET 一个只读接口，返回 JSON 文本。不跟随跨站重定向。
func spaGET(ctx context.Context, cl *http.Client, base *url.URL, path string, timeout int) (string, bool) {
	u := *base
	u.Path, u.RawQuery, u.Fragment = path, "", ""
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0")
	req.Header.Set("Accept", "application/json,*/*")
	resp, err := cl.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, spaMaxAPIBytes))
	s := strings.TrimSpace(string(b))
	if !strings.HasPrefix(s, "{") && !strings.HasPrefix(s, "[") {
		return "", false
	}
	return s, true
}

// spaJSONProductName 从登录页配置类 JSON 里取产品名（platformName 优先）。
func spaJSONProductName(body string) string {
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return ""
	}
	order := []string{"platformname", "productname", "navtext", "logintext", "sysname", "systemname", "name"}
	found := map[string]string{}
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				lk := strings.ToLower(k)
				if s, ok := val.(string); ok {
					s = strings.TrimSpace(s)
					if s != "" && len([]rune(s)) <= 60 && spaKeyWhitelist[lk] {
						if _, exists := found[lk]; !exists {
							found[lk] = s
						}
					}
					continue
				}
				walk(val)
			}
		case []any:
			for _, it := range t {
				walk(it)
			}
		}
	}
	walk(v)
	for _, k := range order {
		if s := found[k]; s != "" {
			return s
		}
	}
	return ""
}

// flattenJSONStrings 把 JSON 里"产品/介绍/版权"类字符串压成 key=value 片段，供规则匹配。
func flattenJSONStrings(body string) []string {
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				lk := strings.ToLower(k)
				if s, ok := val.(string); ok {
					s = strings.TrimSpace(s)
					if s == "" || len([]rune(s)) > 300 {
						continue
					}
					if spaKeyWhitelist[lk] {
						out = append(out, k+"="+s)
					}
					continue
				}
				walk(val)
			}
		case []any:
			for _, it := range t {
				walk(it)
			}
		}
	}
	walk(v)
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func kvKey(s string) string {
	if i := strings.IndexByte(s, '='); i > 0 {
		return s[:i]
	}
	return s
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
