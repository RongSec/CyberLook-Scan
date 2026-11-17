package svcid

// 真正的浏览器渲染（可选）。
//
// 前面 spa.go 做的是"不启浏览器"的取证：抓 JS、调只读接口。它能覆盖大部分
// 前端渲染型系统，但有三类仍然拿不到：
//
//	① 产品名只在脚本运行后才写进 <title>（不在 JS 静态字符串里，是拼出来的）
//	② 页面必须走完一轮前端路由/鉴权跳转才有内容
//	③ 关键线索在渲染后的 DOM 里（菜单名、页脚版权、导航标题）
//
// 这里用外部 chromium 的 --dump-dom 补最后一跳：真跑一遍 JS，拿渲染后的 DOM。
// 代价是每个端口 5~8 秒（进程启动 + 页面加载），所以：
//   - 只在 -render 打开时启用；
//   - 只在前面所有手段都没拿到可信产品名时才跑；
//   - 找不到 chromium 就静默跳过（节点镜像默认不带浏览器，不强依赖）。

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// rendererBinaries 常见发行版/镜像里的浏览器可执行文件名与路径
var rendererBinaries = []string{
	"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome",
	"/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/lib/chromium/chromium",
	"/usr/bin/google-chrome",
}

// FindRenderer 返回可用的浏览器路径，找不到返回空串。
// 结果不做缓存：节点上装了又卸的情况不值得为几毫秒加状态。
func FindRenderer() string {
	for _, b := range rendererBinaries {
		if p, err := exec.LookPath(b); err == nil && p != "" {
			return p
		}
	}
	return ""
}

// RenderPage 用 headless 浏览器打开 url，返回渲染后的 HTML（含 JS 执行结果）。
func RenderPage(ctx context.Context, bin, url string, timeout time.Duration) (string, bool) {
	if bin == "" {
		return "", false
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(rctx, bin,
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--hide-scrollbars",
		"--ignore-certificate-errors",
		"--disable-features=IsolateOrigins,site-per-process",
		"--virtual-time-budget=6000",
		"--dump-dom",
		url,
	)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return "", false
	}
	// 只需要能跑规则和取标题，超过 512KB 的 DOM 截断（管理台页面通常 <100KB）
	s := string(out)
	if len(s) > 512<<10 {
		s = s[:512<<10]
	}
	return s, true
}

// htmlToText 把渲染后的 DOM 压成可见文本（去 script/style/tag），供规则匹配与落库。
// 这一步不做严格解析：目的是让"菜单名/页脚版权/系统名"这些字面量能被规则看到。
func htmlToText(h string) string {
	s := h
	for _, tag := range []string{"script", "style", "noscript", "svg"} {
		for {
			i := strings.Index(strings.ToLower(s), "<"+tag)
			if i < 0 {
				break
			}
			j := strings.Index(strings.ToLower(s[i:]), "</"+tag+">")
			if j < 0 {
				s = s[:i]
				break
			}
			s = s[:i] + " " + s[i+j+len(tag)+3:]
		}
	}
	var b strings.Builder
	deep := false
	for _, r := range s {
		switch {
		case r == '<':
			deep = true
			b.WriteByte(' ')
		case r == '>':
			deep = false
		case !deep:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
