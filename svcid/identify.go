package svcid

// 识别层编排：协议探针（自研） → HTTP 抓页 + favicon → 全量 web 规则匹配

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Service 一个端口的识别结果
type Service struct {
	IP       string   `json:"ip"`
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Product  string   `json:"product"`
	Version  string   `json:"version"`
	Banner   string   `json:"banner,omitempty"`
	TLS      bool     `json:"tls"`
	Source   string   `json:"source"` // probe / web-rule / http-title / win-probe / service-probe / port-hint
	Evidence []string `json:"evidence,omitempty"`
	Score    int      `json:"score"`

	// 平台 ingestService 消费的字段（与 TscanPlus 的 ScanResult 对齐）
	Title        string `json:"title,omitempty"`        // 页面 <title>（非产品名）
	StatusCode   string `json:"statusCode,omitempty"`   // HTTP 状态码
	BodyLen      int    `json:"bodyLen"`                // HTTP 响应体长度
	Body         string `json:"body,omitempty"`         // HTTP 响应体（算页面 SimHash 用）
	OS           string `json:"os,omitempty"`           // SMB/RDP 握手拿到的 OS
	Fingerprint  string `json:"fingerprint,omitempty"` // 技术栈（产品+版本，逗号分隔）
}

// IdentOptions 识别参数
type IdentOptions struct {
	Rules        *RuleSet
	Probes       *ProbeIndex // FingerprintHub service 全量主动探针索引
	ProbeTimeout time.Duration // 默认 1.5s
	HTTPTimeout  time.Duration // 默认 4s
	MaxBodyBytes int64         // 默认 64KB

	// DeepSPA 开启空壳 SPA 的二次取证（抓同源 JS + 只读配置接口）。
	// 关掉时只做静态匹配，速度快但识别不出"前端渲染型"系统。
	DeepSPA bool
	// SPABudget 是单个端口上 SPA 取证的总时间上限，默认 6s。
	SPABudget time.Duration

	// Render 打开浏览器渲染兜底（需要机器上有 chromium，见 render.go）。
	// 只在前面所有手段都没拿到可信产品名时才跑，单端口约 5~8 秒。
	Render        bool
	RenderBin     string        // FindRenderer() 的结果，空表示不可用
	RenderTimeout time.Duration // 默认 8s
}

// Identify 识别单个开放端口
func Identify(ctx context.Context, ip string, port int, opt IdentOptions) Service {
	if opt.ProbeTimeout <= 0 {
		opt.ProbeTimeout = 1500 * time.Millisecond
	}
	if opt.HTTPTimeout <= 0 {
		opt.HTTPTimeout = 4 * time.Second
	}
	if opt.MaxBodyBytes <= 0 {
		opt.MaxBodyBytes = 64 << 10
	}
	res := Service{IP: ip, Port: port}

	// 1) 协议探针（被动优先）
	pr := Probe(ctx, ip, port, opt.ProbeTimeout)
	res.Protocol = pr.Protocol
	res.Version = pr.Version
	res.Banner = pr.Banner
	if pr.Product != "" {
		res.Product = normalizeProduct(pr.Product)
		res.Source = "probe"
	}

	// 1.5) Windows 系主动握手：445/139/3389/135/动态 RPC 上拿真实 OS/主机名
	if res.Product == "" {
		if isWindowsPort(port) {
			if p, v, extra, ban, ok := probeWindows2(ctx, ip, port, opt.ProbeTimeout); ok {
				if p != "" {
					res.Product = normalizeProduct(p)
					res.Source = "win-probe"
				}
				if v != "" {
					res.Version = v
				}
				if extra != "" {
					res.OS = extra
				}
				res.Banner = mergeExtra(ban, extra)
			}
		}
	}

	// 2) HTTP：抓页面 + favicon，跑全量 web 规则
	if isHTTPish(pr, port) {
		httpOpt := opt
		// SPA 取证要复用同一个 client（同 TLS 放宽、同不跟跨站重定向）
		cl := &http.Client{
			Timeout: opt.HTTPTimeout,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				DisableKeepAlives: true,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		if pr.Product == "" && (pr.Protocol == "tcp" || pr.Protocol == "msrpc") {
			httpOpt.HTTPTimeout = 2500 * time.Millisecond // 未知端口兜底，短超时
		}
		if hdrs, body, title, mmh3, md5h, certHint, status, isTLS, ok, pageURL := grabHTTP(ctx, ip, port, httpOpt); ok {
			res.Title, res.StatusCode, res.Body, res.BodyLen = title, status, body, len(body)
			res.TLS = isTLS
			if res.Protocol == "" || res.Protocol == "tcp" {
				if isTLS {
					res.Protocol = "https"
				} else {
					res.Protocol = "http"
				}
			}
			if opt.Rules != nil {
				hits := opt.Rules.MatchWeb(hdrs, body, title, mmh3, md5h)
				// 精度优先：单个弱词命中的产品（score<15）不并入多技术栈，避免一个页面报 4 个产品
				var strong []Hit
				for _, h := range hits {
					if h.Score >= 15 {
						strong = append(strong, h)
					}
				}
				if len(strong) == 0 && len(hits) > 0 {
					strong = hits[:1]
				}
				hits = strong
				if len(hits) > 0 {
					// 多技术栈并列（tscan 也是这样：Windows Server,Microsoft-IIS/8.5,Microsoft-ASP.NET）
					seen := map[string]bool{}
					var prods []string
					for _, h := range hits {
						p := strings.TrimSpace(h.Product)
						if p == "" || seen[strings.ToLower(p)] {
							continue
						}
						seen[strings.ToLower(p)] = true
						prods = append(prods, p)
						if len(prods) >= 3 {
							break
						}
					}
					res.Product = strings.Join(prods, ",")
					res.Score = hits[0].Score
					res.Source = "web-rule"
					for i, h := range hits {
						if i >= 5 {
							break
						}
						res.Evidence = append(res.Evidence, h.RuleID+"("+h.Name+")")
					}
				}
			}
			// 规则只命中"Web 服务器"这类基础设施，而标题明确指向某个系统时，
			// 标题才是真正要的信息（实测：Graylog 的页面被报成 nginx，
			// 因为 Graylog 那条规则要求两个词同时出现，页面上只有一个）。
			if res.Source == "web-rule" && isInfraProduct(res.Product) && title != "" && !isJunkTitle(title) {
				res.Product = title
				res.Source = "http-title"
			}
			// 规则给出"通用 HTTP 服务"这类等于没说的产品名时，标题里的信息更多
			// （实测：IBM Storwize V7000 的登录页被某条通用规则报成 Generic HTTP Server）
			if res.Source == "web-rule" && isGenericProduct(res.Product) && title != "" && !isJunkTitle(title) {
				res.Product = title
				res.Source = "http-title"
			}
			if res.Product == "" && title != "" && !isJunkTitle(title) {
				res.Product = title
				res.Source = "http-title"
			}
			// TLS 证书 CN/O 在内网信噪比很高（自签证书常直接写单位名/系统名）
			if res.Product == "" && certHint != "" {
				res.Product = certHint
				res.Source = "tls-cert"
			}
			// HTTP 头/页面里的产品与版本（nginx/1.24、IIS/8.5、Tomcat/8.5.61…）
			if hp, hv := extractHTTPVersion(hdrs, body); hp != "" || hv != "" {
				if res.Product == "" {
					res.Product = hp
					res.Source = "http-version"
				}
				if res.Version == "" {
					res.Version = hv
				}
			}

			// 2.5) 空壳 SPA 二次取证：静态匹配拿不到产品时，抓同源 JS + 只读配置接口。
			// 这类系统（NGSOC 门户、大模型护栏、各类管理台）把产品名放在接口返回里，
			// 浏览器打开能看到，纯 HTTP 抓取只能拿到一个空壳 <div id="app">。
			// 只在"当前还没有可信产品名"时触发，避免给每个 200 页面都加一轮请求。
			if opt.DeepSPA && looksLikeSPA(body) && weakProduct(res.Product, res.Source) {
				budget := opt.SPABudget
				if budget <= 0 {
					budget = 6 * time.Second
				}
				sctx, cancel := context.WithTimeout(ctx, budget)
				spa := spaEnrich(sctx, cl, pageURL, body, int(opt.HTTPTimeout/time.Millisecond))
				cancel()
				if spa.Title != "" && res.Title == "" {
					res.Title = spa.Title
				}
				if spa.Corpus != "" && opt.Rules != nil {
					// 用补语料再跑一次规则：接口里的 platformName / platformIntroduction
					// 往往就是最权威的产品名，比页面残留词可靠得多。
					if hits := opt.Rules.MatchWeb(hdrs, body+"\n"+spa.Corpus, res.Title, mmh3, md5h); len(hits) > 0 {
						res.Product = strings.TrimSpace(hits[0].Product)
						res.Score = hits[0].Score
						res.Source = "spa-rule"
						res.Evidence = append(res.Evidence, hits[0].RuleID+"("+hits[0].Name+")")
					}
				}
				if res.Product == "" && spa.Title != "" {
					res.Product = spa.Title
					res.Source = "spa-title"
				}
				for _, e := range spa.APIHits {
					res.Evidence = append(res.Evidence, e)
				}
				if spa.JSNum > 0 {
					res.Evidence = append(res.Evidence, "spa-js:"+strconv.Itoa(spa.JSNum))
				}
			}

			// 2.6) 浏览器渲染兜底：真跑一遍 JS，拿渲染后的 DOM。
			// 静态抓取和"抓 JS+接口"都失效时才用（每端口 5~8 秒，成本最高）。
			if opt.Render && opt.RenderBin != "" && pageURL != "" && weakProduct(res.Product, res.Source) {
				u := strings.TrimSuffix(pageURL, "/")
				if u == "" {
					u = "https://" + net.JoinHostPort(ip, strconv.Itoa(port)) + "/"
				}
				if dom, rok := RenderPage(ctx, opt.RenderBin, u, opt.RenderTimeout); rok {
					text := htmlToText(dom)
					rt := extractTitle(dom)
					if rt != "" && !isJunkTitle(rt) {
						res.Title = rt
					}
					if opt.Rules != nil {
						if hits := opt.Rules.MatchWeb(hdrs, dom+"\n"+text, res.Title, mmh3, md5h); len(hits) > 0 {
							res.Product = strings.TrimSpace(hits[0].Product)
							res.Score = hits[0].Score
							res.Source = "render-rule"
							res.Evidence = append(res.Evidence, hits[0].RuleID+"("+hits[0].Name+")")
						}
					}
					if res.Product == "" && res.Title != "" && !isJunkTitle(res.Title) {
						res.Product = res.Title
						res.Source = "render-title"
					}
					res.Evidence = append(res.Evidence, "render-dom:"+strconv.Itoa(len(dom)))
				}
			}
		}
	}
	// 3) 主动探针：被动拿不到 banner 的端口，用 FingerprintHub 全量 service 规则探测
	//    （只对还没拿到产品的端口执行，且每端口最多 3 组 probe）
	if res.Product == "" && opt.Probes != nil {
		if p, ev, ok := opt.Probes.RunServiceProbes(ctx, ip, port, 3); ok {
			res.Product, res.Source = p, "service-probe"
			res.Evidence = append(res.Evidence, ev)
		}
	}
	if res.Product == "" && res.Protocol != "" && res.Protocol != "tcp" {
		res.Product = strings.ToUpper(res.Protocol)
		res.Source = "port-hint"
	}
	// normalizeProduct 会把 "A-B-C" 拆成三段再大写首字母，段落里原有的多余空格会留下来
	// （实测 "AS2200G2 KWL 01   Login   Inspur AS2200G2"），这里统一折叠成单空格。
	res.Product = strings.Join(strings.Fields(normalizeProduct(res.Product)), " ")
	if len([]rune(res.Product)) < 2 {
		res.Product = ""
	}
	// 技术栈字符串（产品+版本），供平台 fingerprint 字段使用
	res.Fingerprint = res.Product
	if res.Version != "" {
		res.Fingerprint = res.Product + "/" + res.Version
	}
	return res
}

func isHTTPish(pr ProbeResult, port int) bool {
	if strings.HasPrefix(strings.ToLower(pr.Protocol), "http") {
		return true
	}
	if pr.Banner != "" && reHTTP.MatchString(pr.Banner) {
		return true
	}
	switch port {
	case 80, 81, 88, 443, 800, 888, 1080, 3000, 3900, 5000, 5601, 5985, 5986,
		7000, 7001, 7002, 8000, 8001, 8008, 8010, 8080, 8081, 8082, 8084, 8086,
		8088, 8090, 8161, 8180, 8443, 8888, 9000, 9001, 9080, 9090, 9200, 9443,
		10000, 10133, 17421, 18080, 47001, 50070:
		return true
	}
	// 被动探针没认出来（tcp/msrpc）：HTTP 是最常见的兜底服务，都试一把
	if pr.Product == "" && (pr.Protocol == "tcp" || pr.Protocol == "msrpc") {
		return true
	}
	return false
}

// grabHTTP 抓页面（容忍 3xx/4xx/自签证书/跨 scheme 重定向），返回 header/body/title/favicon 双哈希/证书线索。
// 关键改动：**任何 HTTP 响应都算成功**（包括 301/403/500），因为 Server 头本身就能定产品；
// 重定向失败时保留上一跳的响应，而不是整体放弃。
func grabHTTP(ctx context.Context, ip string, port int, opt IdentOptions) (headers, body, title, mmh3, md5h, certHint string, statusCode string, isTLS, ok bool, pageURL string) {
	schemes := []string{"http", "https"}
	if port == 443 || port == 8443 || port == 9443 {
		schemes = []string{"https", "http"}
	}
	cl := &http.Client{
		Timeout: opt.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		// 手动跟重定向：上一跳响应也要留着
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	bestHeaders, bestBody, bestTitle, bestMMH3, bestMD5, bestCert := "", "", "", "", "", ""
	bestStatus, bestURL := "", ""
	bestTLS, bestOK, bestScore := false, false, -1

	for _, sch := range schemes {
		hdrs, body, title, mmh3, md5h, cert, status, finalURL, tlsOK, ok2, score := httpFetchFollow(ctx, cl, sch, ip, port, opt)
		if !ok2 {
			continue
		}
		if score > bestScore {
			bestHeaders, bestBody, bestTitle, bestMMH3, bestMD5, bestCert = hdrs, body, title, mmh3, md5h, cert
			bestStatus, bestURL = status, finalURL
			bestTLS, bestOK, bestScore = tlsOK, true, score
		}
		if score >= 300 {
			break // 2xx 已是最好的
		}
	}
	return bestHeaders, bestBody, bestTitle, bestMMH3, bestMD5, bestCert, bestStatus, bestTLS, bestOK, bestURL
}

// httpFetchFollow 手动跟随同 host 重定向（最多 3 跳），任一跳有响应就算成功
func httpFetchFollow(ctx context.Context, cl *http.Client, scheme, ip string, port int, opt IdentOptions) (
	hdrs, body, title, mmh3, md5h, certHint string, statusCode, finalURL string, isTLS, ok bool, score int) {
	host := net.JoinHostPort(ip, strconv.Itoa(port))
	url := scheme + "://" + host + "/"
	score = -1
	for hop := 0; hop < 3; hop++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0")
		resp, err := cl.Do(req)
		if err != nil {
			break
		}
		var sb strings.Builder
		for k, vs := range resp.Header {
			sb.WriteString(k + ": " + strings.Join(vs, "; ") + "\n")
		}
		// TLS 证书 CN/O（内网自签证书常含单位/系统名）
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			sub := resp.TLS.PeerCertificates[0].Subject
			cn := strings.TrimSpace(sub.CommonName)
			org := strings.TrimSpace(strings.Join(sub.Organization, ","))
			ou := strings.TrimSpace(strings.Join(sub.OrganizationalUnit, ","))
			// OU 也要带上：BMC / 设备类自签证书常把产品线写在 OU
			// （AMI MegaRAC 的证书就是 O=AMI + OU=MEGARAC + CN=ami.com）
			sb.WriteString("TLS-CN: " + cn + "\nTLS-O: " + org + "\nTLS-OU: " + ou + "\n")
			certHint = cn
			if certHint == "" {
				certHint = org
			}
			isTLS = true
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, opt.MaxBodyBytes))
		_ = resp.Body.Close()
		// 内网存量系统大量是 GB2312/GBK 输出，不转码会导致中文标题变乱码、
		// 中文规则全部匹配不上（见 charset.go 顶部说明）
		b = ensureUTF8(b, resp.Header.Get("Content-Type"))
		status := resp.StatusCode
		// 记录最好的一跳（2xx 优先于 3xx 优先于 4xx/5xx）
		rank := 100
		switch {
		case status >= 200 && status < 300:
			rank = 300
		case status >= 300 && status < 400:
			rank = 200
		}
		if rank > score {
			hdrs, body, title = sb.String(), string(b), extractTitle(string(b))
			statusCode = strconv.Itoa(status)
			finalURL = url
			score = rank
			if fb, e := fetchFavicon(cl, scheme, ip, port); e == nil && len(fb) > 0 {
				md5h = FaviconHashes(fb)
				mmh3 = strconv.Itoa(int(FaviconMMH3(fb)))
			}
			ok = true
		}
		// 跟随重定向（同 host）
		if status >= 300 && status < 400 {
			loc := strings.TrimSpace(resp.Header.Get("Location"))
			if loc == "" {
				break
			}
			if strings.HasPrefix(loc, "/") {
				url = scheme + "://" + host + loc
				continue
			}
			if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
				// 只跟同 IP 的重定向，避免跨资产污染口径
				if strings.Contains(loc, ip) {
					url = loc
					continue
				}
			}
			break
		}
		break
	}
	return hdrs, body, title, mmh3, md5h, certHint, statusCode, finalURL, isTLS, ok, score
}

func fetchFavicon(cl *http.Client, scheme, ip string, port int) ([]byte, error) {
	u := scheme + "://" + net.JoinHostPort(ip, strconv.Itoa(port)) + "/favicon.ico"
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, io.ErrUnexpectedEOF
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<10))
}

func extractTitle(body string) string {
	low := strings.ToLower(body)
	i := strings.Index(low, "<title")
	if i < 0 {
		return ""
	}
	gt := strings.IndexByte(body[i:], '>')
	if gt < 0 {
		return ""
	}
	start := i + gt + 1
	j := strings.Index(low[start:], "</title>")
	if j < 0 {
		return ""
	}
	t := strings.TrimSpace(body[start : start+j])
	// 标题里常有换行、Tab、连续空格（模板拼接的产物），
	// 直接当产品名会写进资产表并带上\n，统一折叠成单空格。
	t = strings.Join(strings.Fields(t), " ")
	if len([]rune(t)) > 120 {
		t = string([]rune(t)[:120])
	}
	return t
}

// isJunkTitle 默认页/错误页标题不算产品名
func isJunkTitle(t string) bool {
	x := strings.ToLower(strings.TrimSpace(t))
	if x == "" {
		return true
	}
	for _, k := range []string{
		"not found", "403 forbidden", "404", "400 bad request", "500 internal",
		"error", "forbidden", "access denied", "unauthorized",
		// 跳转页/状态页的标题会被 http-title 兜底当产品名（实测出现过 "302 Found"）
		"301 moved", "302 found", "303 see other", "307 temporary", "308 permanent",
		"moved permanently", "temporary redirect", "object moved",
		"502 bad", "503 service", "504 gateway", "bad gateway", "service unavailable",
		"default page", "default web site", "iis windows", "apache2 ubuntu", "apache2 debian",
		"未找到", "错误", "禁止访问", "拒绝访问", "无法访问", "未授权",
		"welcome", "index of", "it works", "test page", "loading", "webserver",
	} {
		if strings.Contains(x, k) {
			return true
		}
	}
	return len([]rune(x)) < 3
}

// isWindowsPort 是否值得做 Windows 系握手
func isWindowsPort(port int) bool {
	switch port {
	case 135, 139, 445, 3389, 5985, 5986, 47001:
		return true
	}
	// Windows 动态 RPC 端口段
	if (port >= 49152 && port <= 49735) || (port >= 53000 && port <= 53100) {
		return true
	}
	return false
}

// probeWindows2 包一层连接
func probeWindows2(ctx context.Context, ip string, port int, timeout time.Duration) (product, version, extra, banner string, ok bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", "", "", "", false
	}
	defer conn.Close()
	return probeWindows(conn, port)
}

// weakProduct 判断当前产品名是否属于"不可信兜底"，值得再做一轮 SPA 取证。
// 强来源：主动探针、Windows 握手、service 探针、web 规则高分命中。
// 弱来源：页面标题、TLS 证书、HTTP 头版本、端口猜测——这些在 SPA 站点上基本是空的或错的。
func weakProduct(product, source string) bool {
	if strings.TrimSpace(product) == "" {
		return true
	}
	switch source {
	case "probe", "win-probe", "service-probe":
		return false
	case "web-rule":
		return false
	case "spa-rule", "spa-title":
		return false
	}
	// http-title / tls-cert / http-version / port-hint 等
	return true
}

// isGenericProduct 判断产品名是否属于"等于没识别"的通用名
func isGenericProduct(p string) bool {
	x := strings.ToLower(strings.TrimSpace(p))
	if x == "" {
		return true
	}
	for _, k := range []string{"generic", "http server", "web server", "unknown", "unidentified"} {
		if strings.Contains(x, k) {
			return true
		}
	}
	switch x {
	case "http", "https", "tcp", "udp", "ssl", "webserver":
		return true
	}
	return false
}

// isInfraProduct 判断产品名是否只表示"这是个 Web 服务器"（不含业务系统信息）。
// 这类名字在资产台账里几乎没有价值——知道是 nginx 并不能告诉人这台机器干什么。
func isInfraProduct(p string) bool {
	parts := strings.Split(p, ",")
	for _, one := range parts {
		x := strings.ToLower(strings.TrimSpace(one))
		x = strings.SplitN(x, "/", 2)[0]
		switch x {
		case "nginx", "apache", "apache httpd", "httpd", "iis", "microsoft-iis",
			"openresty", "tengine", "lighttpd", "caddy", "http", "https",
			"generic http server", "apache-coyote", "tomcat":
		default:
			return false
		}
	}
	return true
}
