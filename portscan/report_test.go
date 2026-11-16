package portscan

import (
	"strings"
	"testing"
	"time"
)

// TestFormatLinesContract 三条日志的固定形态。
//
// 这些行不只给人看：平台侧 internal/scanner/progline.go 用正则从里面取
// 探针进度/速率/命中数/ETA。改文案必须同步改那边的解析，否则表现为
// "进度永远 0%"——所以把字段顺序与分隔符钉在测试里。
func TestFormatLinesContract(t *testing.T) {
	p := FormatParamsLine(ReportParams{
		Concurrency: 600, TimeoutMs: 1000, Identify: false,
		IdentWorkers: 0, FullFinger: false, Targets: 1, Ports: 65535,
	})
	for _, want := range []string{"[扫描] 参数：", "并发 600", "超时 1000ms", "识别=关闭", "1 目标 × 65535 端口 = 65535 探针"} {
		if !strings.Contains(p, want) {
			t.Errorf("参数行缺 %q：%s", want, p)
		}
	}

	g := FormatProgressLine(ReportProgress{Done: 30000, Total: 65535, Open: 6, Ident: 6, Elapsed: 12 * time.Second})
	for _, want := range []string{"[扫描] 进行中 45%", "30000/65535 探针", "已用 12s", "剩余 ", "探针/秒", "开放 6 个，识别 6 个"} {
		if !strings.Contains(g, want) {
			t.Errorf("进度行缺 %q：%s", want, g)
		}
	}

	d := FormatDoneLine(ReportDone{Probes: 65535, Total: 65535, Elapsed: 26 * time.Second, Open: 6, Ident: 6})
	for _, want := range []string{"[扫描] 完成 65535/65535 探针", "耗时 26s", "平均 ", "开放 6 个，识别 6 个"} {
		if !strings.Contains(d, want) {
			t.Errorf("完成行缺 %q：%s", want, d)
		}
	}
}

// TestProgressEdgeCases 进度边界：0 总数为 0%，完成时剩余 0s，早期样本不出现负 ETA
func TestProgressEdgeCases(t *testing.T) {
	if got := FormatProgressLine(ReportProgress{Done: 0, Total: 0}); !strings.Contains(got, "0%") {
		t.Errorf("Total=0 应为 0%%: %s", got)
	}
	if got := FormatProgressLine(ReportProgress{Done: 100, Total: 100, Elapsed: time.Second}); !strings.Contains(got, "剩余 0s") {
		t.Errorf("完成时应显示剩余 0s: %s", got)
	}
	// Done=0 + 有 Total：速率 0，ETA 只能是"计算中"，不能算出巨大数字或负数
	if got := FormatProgressLine(ReportProgress{Done: 0, Total: 1000, Elapsed: time.Second}); !strings.Contains(got, "剩余 计算中") {
		t.Errorf("零速率应为计算中: %s", got)
	}
	if got := FormatProgressLine(ReportProgress{Done: 10, Total: 1000, Elapsed: 0}); strings.Contains(got, "-") && !strings.Contains(got, "探针/秒") {
		t.Errorf("Elapsed=0 不应崩: %s", got)
	}
}

// TestProgressNoOverflow 百分比封顶 100，避免 done>total（重试/重复投递）时显示 137%
func TestProgressNoOverflow(t *testing.T) {
	got := FormatProgressLine(ReportProgress{Done: 200, Total: 100, Elapsed: time.Second})
	if !strings.Contains(got, "100%") {
		t.Errorf("应封顶 100%%: %s", got)
	}
}
