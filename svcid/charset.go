package svcid

// 页面编码归一。
//
// 内网存量的 IIS / 老 Java 系统大量使用 GB2312 / GBK 输出，声明确实写在 HTML 里
// （`<meta charset="gb2312">`），但 Go 不认——它是按字节读的，直接当 UTF-8 用就会得到
// `403 - ��ֹ����: ���ʱ��ܾ���` 这种标题。后果不只是显示难看：
//
//	① 规则匹配用的是小写化后的字节流，中文规则（"明御数据库审计""大华""海康"）永远匹配不上；
//	② 标题落库是乱码，人看了不知道是什么系统，等于没识别。
//
// 这里在抓取阶段统一转成 UTF-8。判定顺序：Content-Type → <meta charset> →
// 非 UTF-8 则按 GB18030 兜底（GB18030 是 GBK/GB2312 的超集，解这两个编码不会出错）。
// 只对文本类响应做处理，二进制（图片/字体/JSON 之外的）原样返回。

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// ensureUTF8 把响应体归一成 UTF-8。返回新切片（不修改入参）。
func ensureUTF8(body []byte, contentType string) []byte {
	if len(body) == 0 {
		return body
	}
	if utf8.Valid(body) && !declaresGB(contentType) && !metaDeclaresGB(body) {
		return body
	}
	if declared := charsetOf(contentType); declared != "" && isUTF8Name(declared) {
		return body
	}
	if meta := metaCharset(body); meta != "" && isUTF8Name(meta) {
		return body
	}
	if !looksTextual(body) {
		return body
	}
	dec := simplifiedchinese.GB18030.NewDecoder()
	if out, err := dec.Bytes(body); err == nil && len(out) > 0 {
		return out
	}
	return body
}

func isUTF8Name(cs string) bool {
	cs = strings.ToLower(strings.TrimSpace(cs))
	return cs == "utf-8" || cs == "utf8"
}

func isGBName(cs string) bool {
	cs = strings.ToLower(strings.TrimSpace(cs))
	return strings.HasPrefix(cs, "gb") || cs == "gb2312" || cs == "gbk" || cs == "gb18030"
}

// charsetOf 从 Content-Type 里取 charset
func charsetOf(ct string) string {
	low := strings.ToLower(ct)
	i := strings.Index(low, "charset=")
	if i < 0 {
		return ""
	}
	rest := low[i+len("charset="):]
	if j := strings.IndexAny(rest, "; \t\r\n\""); j >= 0 {
		rest = rest[:j]
	}
	return strings.Trim(rest, `"' `)
}

func declaresGB(ct string) bool { return isGBName(charsetOf(ct)) }

// metaCharset 取 <meta charset=...> 或 <meta http-equiv="Content-Type" content="...; charset=...">
func metaCharset(body []byte) string {
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	low := bytes.ToLower(head)
	if i := bytes.Index(low, []byte("charset=")); i >= 0 {
		rest := bytes.TrimLeft(low[i+len("charset="):], " \t\"'")
		if len(rest) > 32 {
			rest = rest[:32]
		}
		end := len(rest)
		for k, c := range rest {
			if c == '"' || c == '\'' || c == '>' || c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '/' {
				end = k
				break
			}
		}
		if end > 0 {
			return string(rest[:end])
		}
	}
	return ""
}

func metaDeclaresGB(body []byte) bool { return isGBName(metaCharset(body)) }

// looksTextual 粗判是否文本响应：含 NUL 字节或出现大量高位乱码就按二进制跳过
func looksTextual(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	sample := b
	if len(sample) > 2048 {
		sample = sample[:2048]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}
	// 出现大量 0x80-0xBF 的孤立续字节，说明多半不是中文编码
	bad := 0
	for _, c := range sample {
		if c >= 0x80 && c < 0xC0 {
			bad++
		}
	}
	return bad*20 < len(sample)
}
