package svcid

// SPA 兜底取证与"词间 and"语义的测试。
//
// 这两块都是"识别准不准"的直接关口：
//   - 内层 condition=and 被当 or 用，会让只沾一个通用词的页面命中产品规则（误报）
//   - 空壳 SPA 不抓 JS/接口，会让前端渲染型系统完全识别不出来（漏报）
// 所以两者都要有可复现的用例钉住。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadRulesFrom 用临时目录里的一份 web 规则建 RuleSet
func loadRulesFrom(t *testing.T, body string) *RuleSet {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "web_fingerprint_v4.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return rs
}

// TestStrictWordAnd matcher 内 condition=and：必须所有词都出现才算命中
func TestStrictWordAnd(t *testing.T) {
	rs := loadRulesFrom(t, `[
	  {"id":"gw-and","info":{"name":"网关","metadata":{"product":"某网关"}},
	   "http":[{"matchers":[{"type":"word","words":["login","loid_regist()"],"condition":"and"}]}]}
	]`)

	// 只出现 login（本轮 10.24.9.103 的真实形态：页面里只有 portal/login）
	if hits := rs.MatchWeb("", `<a href="./apex-base/portal/login/index.js"></a>`, "", "", ""); len(hits) != 0 {
		t.Fatalf("只命中一个词却报出产品: %+v", hits)
	}
	// 两个词都在才命中
	if hits := rs.MatchWeb("", "login ... loid_regist() ...", "", "", ""); len(hits) != 1 {
		t.Fatalf("两个词都在却没命中: %+v", hits)
	}
}

// TestWordOrDefault 不写 condition（默认 or）时，任一词命中即通过——保持原语义不变
func TestWordOrDefault(t *testing.T) {
	rs := loadRulesFrom(t, `[
	  {"id":"any-or","info":{"name":"任一","metadata":{"product":"任一命中"}},
	   "http":[{"matchers":[{"type":"word","words":["alpha-token","beta-token"]}]}]}
	]`)
	if hits := rs.MatchWeb("", "beta-token", "", "", ""); len(hits) != 1 {
		t.Fatalf("or 语义应命中: %+v", hits)
	}
}

// TestLooksLikeSPA 空壳判定：内容极少 + 有外链脚本 + 有挂载点/空标题
func TestLooksLikeSPA(t *testing.T) {
	spa := `<html><head><base href="/static/"><title></title></head>
	<body><div id="app"></div><script src="./x/bootstrap.js"></script></body></html>`
	if !looksLikeSPA(spa) {
		t.Fatal("典型空壳 SPA 未识别")
	}
	plain := `<html><head><title>浪潮存储 AS2200G2</title></head><body>真实内容</body></html>`
	if looksLikeSPA(plain) {
		t.Fatal("有标题的普通页面被误判为 SPA")
	}
	big := `<html><body><div id="app"></div><script src="/a.js"></script>` + strings.Repeat("x", spaMaxHTML) + `</body></html>`
	if looksLikeSPA(big) {
		t.Fatal("内容超限的页面不应进入 SPA 取证（浪费预算）")
	}
}

// TestPickSPAPaths 只挑只读信息类接口，登录/验证码/改状态一律不碰
func TestPickSPAPaths(t *testing.T) {
	src := `
	  "/api/apex/portal/v1/loginPage"
	  "/ngsoc/AUTH/api/v3/verifyCode"
	  "/ngsoc/AUTH/api/v3/login"
	  "/api/apex/portal/v1/global/customize/picture?id=logo"
	  "/api/v1/system/status"
	  "/api/v1/user/delete"
	  "/static/apex-base/portal/login/js/bootstrap.js"
	`
	got := pickSPAPaths(src)
	want := map[string]bool{
		"/api/apex/portal/v1/loginPage": true,
		"/api/apex/portal/v1/global/customize/picture?id=logo": true,
		"/api/v1/system/status": true,
	}
	if len(got) == 0 {
		t.Fatal("一个接口都没挑出来")
	}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("不该请求的路径被选中: %s（全部: %v）", p, got)
		}
	}
	if len(got) > spaMaxAPICalls {
		t.Fatalf("超过请求上限: %d", len(got))
	}
}

// TestSPAJSONProductName 登录页配置接口里的 platformName 就是最权威的产品名
func TestSPAJSONProductName(t *testing.T) {
	body := `{"code":"Success","data":{"customize":{
	  "platformName":"大模型安全护栏",
	  "platformNameColor":"#FFFFFF",
	  "platformIntroduction":"深信服大模型安全护栏，基于大小模型混合架构…",
	  "navText":"大模型安全护栏"}}}`
	if got := spaJSONProductName(body); got != "大模型安全护栏" {
		t.Fatalf("platformName 没取到: %q", got)
	}
	kvs := flattenJSONStrings(body)
	joined := strings.Join(kvs, "|")
	for _, want := range []string{"platformName=大模型安全护栏", "platformIntroduction="} {
		if !strings.Contains(joined, want) {
			t.Fatalf("补语料缺 %q: %s", want, joined)
		}
	}
}

// TestSPAEnrichEndToEnd 起一个假的"空壳 SPA + 配置接口"，验证整条链路：
// 按 <base href> 抓 JS → 抽接口 → 取 platformName
func TestSPAEnrichEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><base href="/static/"><title></title></head>
		  <body><div id="app"></div>
		  <script src="./apex-base/portal/login/js/bootstrap.js"></script></body></html>`))
	})
	mux.HandleFunc("/static/apex-base/portal/login/js/bootstrap.js", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`x=1;$.ajax({url:"/api/apex/portal/v1/loginPage"});` + strings.Repeat("//pad\n", 60)))
	})
	mux.HandleFunc("/api/apex/portal/v1/loginPage", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"customize":{"platformName":"大模型安全护栏","platformIntroduction":"深信服大模型安全护栏"}}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/login", nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, spaMaxHTML)
	n, _ := resp.Body.Read(buf)
	_ = resp.Body.Close()
	html := string(buf[:n])

	cl := &http.Client{}
	res := spaEnrich(req.Context(), cl, srv.URL+"/login", html, 3000)
	if res.Title != "大模型安全护栏" {
		t.Fatalf("Title 未取到: %q (js=%d, api=%v)", res.Title, res.JSNum, res.APIHits)
	}
	if !strings.Contains(res.Corpus, "platformIntroduction=") {
		t.Fatalf("补语料不完整: %s", res.Corpus)
	}
	if res.JSNum != 1 {
		t.Fatalf("JS 抓取数量异常: %d", res.JSNum)
	}
}
