package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rulesJSON 生成 n 条最小规则 JSON
func rulesJSON(prefix string, n int) string {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":"%s-%d","info":{"name":"r%d"},"http":[{"matchers":[{"type":"word","words":["tok-%s-%d"]}]}]}`, prefix, i, i, prefix, i)
	}
	b.WriteByte(']')
	return b.String()
}

// stubHub 起一个假 FingerprintHub，按路径返回给定内容（不存在的 key = 404）。
// 同时把重试退避缩短，避免失败路径测试等待真实 backoff。
func stubHub(t *testing.T, routes map[string]string) string {
	t.Helper()
	oldBackoff := retryBackoffBase
	retryBackoffBase = time.Millisecond
	t.Cleanup(func() { retryBackoffBase = oldBackoff })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	old := fingerprintHubRawBase
	fingerprintHubRawBase = srv.URL
	t.Cleanup(func() { fingerprintHubRawBase = old })
	return srv.URL
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRulesUpdateHappyPath 单文件落地 + 旧分片被清理（新条数 ≥ 旧总和）
func TestRulesUpdateHappyPath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "service_fingerprint_v4.part00.json"), rulesJSON("p0", 3))
	writeFile(t, filepath.Join(dir, "service_fingerprint_v4.part01.json"), rulesJSON("p1", 4))
	writeFile(t, filepath.Join(dir, "web_fingerprint_v4.json"), rulesJSON("old", 1))

	stubHub(t, map[string]string{
		"main/web_fingerprint_v4.json":     rulesJSON("new", 5),
		"main/service_fingerprint_v4.json": rulesJSON("svc", 10),
	})

	if code := runRulesUpdate([]string{"-rules", dir}, ""); code != 0 {
		t.Fatalf("退出码 = %d，期望 0", code)
	}

	// web 单文件被覆盖
	web, err := os.ReadFile(filepath.Join(dir, "web_fingerprint_v4.json"))
	if err != nil {
		t.Fatal(err)
	}
	var wv []map[string]any
	if err := json.Unmarshal(web, &wv); err != nil || len(wv) != 5 {
		t.Errorf("web 文件未更新: len=%d err=%v", len(wv), err)
	}
	// service 单文件生成
	svcPath := filepath.Join(dir, "service_fingerprint_v4.json")
	svc, err := os.ReadFile(svcPath)
	if err != nil {
		t.Fatalf("service 单文件未生成: %v", err)
	}
	var sv []map[string]any
	if err := json.Unmarshal(svc, &sv); err != nil || len(sv) != 10 {
		t.Errorf("service 条数不对: len=%d err=%v", len(sv), err)
	}
	// 旧分片已删除
	for _, p := range []string{"service_fingerprint_v4.part00.json", "service_fingerprint_v4.part01.json"} {
		if _, err := os.Stat(filepath.Join(dir, p)); !os.IsNotExist(err) {
			t.Errorf("旧分片 %s 未被删除", p)
		}
	}
	// 无残留 .tmp
	left, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(left) != 0 {
		t.Errorf("残留临时文件: %v", left)
	}
	// 落地文件仍能被 svcid.Load 的目录模式解析（文件名归类正确）
	assertRuleCounts(t, dir, 5, 10)
}

// TestRulesUpdateKeepsShardsWhenFewer 新单文件条数 < 旧分片总和 → 保留分片，不丢规则
func TestRulesUpdateKeepsShardsWhenFewer(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "service_fingerprint_v4.part00.json"), rulesJSON("p0", 6))
	writeFile(t, filepath.Join(dir, "service_fingerprint_v4.part01.json"), rulesJSON("p1", 6))

	stubHub(t, map[string]string{
		"main/web_fingerprint_v4.json":     rulesJSON("w", 2),
		"main/service_fingerprint_v4.json": rulesJSON("s", 5), // 少于 12
	})
	if code := runRulesUpdate([]string{"-rules", dir}, ""); code != 0 {
		t.Fatalf("退出码 = %d，期望 0", code)
	}
	for _, p := range []string{"service_fingerprint_v4.part00.json", "service_fingerprint_v4.part01.json"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("条数不足时分片应保留，但 %s 不见了: %v", p, err)
		}
	}
	// 单文件 + 分片共存时 Load 会累加，这里确认共存而非替换
	assertRuleCounts(t, dir, 2, 17)
}

// TestRulesUpdateNetworkFailure 全部下载失败 → 退出码 1，原文件保持不变
func TestRulesUpdateNetworkFailure(t *testing.T) {
	dir := t.TempDir()
	orig := rulesJSON("keep", 3)
	writeFile(t, filepath.Join(dir, "web_fingerprint_v4.json"), orig)
	writeFile(t, filepath.Join(dir, "service_fingerprint_v4.part00.json"), rulesJSON("p", 2))

	stubHub(t, map[string]string{}) // 一切请求 404
	if code := runRulesUpdate([]string{"-rules", dir}, ""); code != 1 {
		t.Fatalf("退出码 = %d，期望 1", code)
	}
	b, err := os.ReadFile(filepath.Join(dir, "web_fingerprint_v4.json"))
	if err != nil || string(b) != orig {
		t.Errorf("失败后不应改动既有规则: err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "service_fingerprint_v4.json")); !os.IsNotExist(err) {
		t.Error("失败后不应生成 service 单文件")
	}
	if _, err := os.Stat(filepath.Join(dir, "service_fingerprint_v4.part00.json")); err != nil {
		t.Error("失败后分片必须保留")
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(left) != 0 {
		t.Errorf("失败后不得残留 .tmp: %v", left)
	}
}

// TestRulesUpdateBadJSON 返回内容不是合法规则 JSON → 不写盘、退出码 1
func TestRulesUpdateBadJSON(t *testing.T) {
	dir := t.TempDir()
	orig := rulesJSON("keep", 1)
	writeFile(t, filepath.Join(dir, "web_fingerprint_v4.json"), orig)
	stubHub(t, map[string]string{
		"main/web_fingerprint_v4.json":     "<html>404 Not Found</html>",
		"main/service_fingerprint_v4.json": rulesJSON("s", 1),
	})
	if code := runRulesUpdate([]string{"-rules", dir}, ""); code != 1 {
		t.Fatalf("退出码 = %d，期望 1", code)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "web_fingerprint_v4.json"))
	if string(b) != orig {
		t.Error("坏 JSON 不得覆盖原文件")
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(left) != 0 {
		t.Errorf("不得残留 .tmp: %v", left)
	}
}

// TestRulesUpdateRefFlag -ref 切换分支：路径带 ref 才命中
func TestRulesUpdateRefFlag(t *testing.T) {
	dir := t.TempDir()
	stubHub(t, map[string]string{
		"v9.9/web_fingerprint_v4.json":     rulesJSON("w", 1),
		"v9.9/service_fingerprint_v4.json": rulesJSON("s", 1),
	})
	if code := runRulesUpdate([]string{"-rules", dir, "-ref", "v9.9"}, ""); code != 0 {
		t.Fatalf("自定义 ref 应成功，退出码 = %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "web_fingerprint_v4.json")); err != nil {
		t.Errorf("文件未落地: %v", err)
	}
}

// TestRulesUpdateRulesFallback 子命令不显式给 -rules 时沿用全局 -rules 值；
// 全局值是文件时写入其父目录。
func TestRulesUpdateRulesFallback(t *testing.T) {
	dir := t.TempDir()
	stubHub(t, map[string]string{
		"main/web_fingerprint_v4.json":     rulesJSON("w", 1),
		"main/service_fingerprint_v4.json": rulesJSON("s", 1),
	})
	fileVal := filepath.Join(dir, "web_fingerprint_v4.json")
	if code := runRulesUpdate(nil, fileVal); code != 0 {
		t.Fatalf("退出码 = %d，期望 0", code)
	}
	if _, err := os.Stat(fileVal); err != nil {
		t.Errorf("应写入 -rules 文件的父目录: %v", err)
	}
	// 逗号列表取第一项
	dir2 := filepath.Join(dir, "sub")
	if code := runRulesUpdate(nil, dir2+","+dir); code != 0 {
		t.Fatalf("退出码 = %d，期望 0", code)
	}
	if _, err := os.Stat(filepath.Join(dir2, "web_fingerprint_v4.json")); err != nil {
		t.Errorf("多路径时应写入第一项目录: %v", err)
	}
}

// TestResolveRuleDir 目录/文件/列表/创建 语义
func TestResolveRuleDir(t *testing.T) {
	base := t.TempDir()
	f := filepath.Join(base, "web_fingerprint_v4.json")
	writeFile(t, f, "[]")
	got, err := resolveRuleDir(f)
	if err != nil || got != base {
		t.Errorf("文件项应取父目录: %s err=%v", got, err)
	}
	got, err = resolveRuleDir(" " + base + " , other")
	if err != nil || got != base {
		t.Errorf("列表应取第一项: %s err=%v", got, err)
	}
	newDir := filepath.Join(base, "nested", "rules")
	got, err = resolveRuleDir(newDir)
	if err != nil || got != newDir {
		t.Errorf("不存在的目录应被创建: %s err=%v", got, err)
	}
	if fi, e := os.Stat(newDir); e != nil || !fi.IsDir() {
		t.Errorf("目录未创建: %v", e)
	}
	if _, err := resolveRuleDir("  "); err == nil {
		t.Error("空 -rules 应报错")
	}
}

// TestAtomicWriteReplacesExisting 目标已存在时仍能原子替换且不残留 tmp
func TestAtomicWriteReplacesExisting(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "x.json")
	writeFile(t, final, "old")
	if err := atomicWrite(final+".tmp", final, []byte("new")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(final)
	if string(b) != "new" {
		t.Errorf("内容未替换: %s", b)
	}
	if _, err := os.Stat(final + ".tmp"); !os.IsNotExist(err) {
		t.Error("tmp 未清理")
	}
}

// assertRuleCounts 用 svcid 的归类规则确认目录下 web/service 条数（避免为此再解析一遍文件名）
func assertRuleCounts(t *testing.T, dir string, wantWeb, wantSvc int) {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 目录 glob：service 单文件与分片共存时累加
	matches, _ := filepath.Glob(filepath.Join(abs, "service_fingerprint_v4*.json"))
	svc := 0
	for _, p := range matches {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		var v []json.RawMessage
		if e := json.Unmarshal(b, &v); e != nil {
			t.Fatalf("%s 不是合法 JSON 数组: %v", filepath.Base(p), e)
		}
		svc += len(v)
	}
	if svc != wantSvc {
		t.Errorf("service 总条数 = %d，期望 %d（文件：%v）", svc, wantSvc, matches)
	}
	b, e := os.ReadFile(filepath.Join(abs, "web_fingerprint_v4.json"))
	if e != nil {
		t.Fatal(e)
	}
	var wv []json.RawMessage
	if e := json.Unmarshal(b, &wv); e != nil {
		t.Fatal(e)
	}
	if len(wv) != wantWeb {
		t.Errorf("web 条数 = %d，期望 %d", len(wv), wantWeb)
	}
}
