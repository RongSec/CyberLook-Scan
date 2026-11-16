package portscan

// 扫描过程统一回显
//
// 为什么放在引擎包里：同一套扫描逻辑有两个入口 ——
//  1) 单独跑二进制（cmd/cyberlook-scan，人工排查用）
//  2) 平台下发的队列单元（节点内嵌调用）
// 两边以前各写各的：CLI 是 `[扫描] 目标 N 个 × 端口 M 个…` + `[进度] 1234/65535（1.9%）开放 2`，
// 平台是 `[自研引擎] 扫描参数：…` + `[自研引擎] 扫描中 45%（…）｜613 探针/秒｜…`。
// 同一个任务在终端和平台日志里长得不一样，对着看要多做一次翻译，排查成本白增。
//
// 现在两个入口都调这里，文案只有一份。改文案只改本文件 + 平台侧四条解析正则。

import (
	"fmt"
	"time"
)

// ReportParams 参数行的输入。
type ReportParams struct {
	Concurrency  int
	TimeoutMs    int
	Identify     bool
	IdentWorkers int
	FullFinger   bool
	Targets      int
	Ports        int
}

// FormatParamsLine 参数行。
//
// 示例：`[扫描] 参数：并发 600，超时 1000ms，识别=关闭（识别并发 0，全量指纹 关闭）；本次 1 目标 × 65535 端口 = 65535 探针`
func FormatParamsLine(p ReportParams) string {
	ident := "关闭"
	if p.Identify {
		ident = "开启"
	}
	finger := "关闭"
	if p.FullFinger {
		finger = "开启"
	}
	return fmt.Sprintf("[扫描] 参数：并发 %d，超时 %dms，识别=%s（识别并发 %d，全量指纹 %s）；本次 %d 目标 × %d 端口 = %d 探针",
		p.Concurrency, p.TimeoutMs, ident, p.IdentWorkers, finger, p.Targets, p.Ports, p.Targets*p.Ports)
}

// ReportProgress 进度行的输入。
type ReportProgress struct {
	Done, Total int64
	Open, Ident int64
	Elapsed     time.Duration
}

// FormatProgressLine 进度行（同一行内自带百分比、已用/剩余、速率、命中）。
//
// 示例：`[扫描] 进行中 45%（29490/65535 探针，已用 12s，剩余 14s）｜2450 探针/秒｜开放 6 个，识别 6 个`
func FormatProgressLine(p ReportProgress) string {
	pct := int64(0)
	if p.Total > 0 {
		pct = p.Done * 100 / p.Total
	}
	if pct > 100 {
		pct = 100
	}
	el := p.Elapsed
	if el <= 0 {
		el = time.Millisecond
	}
	pps := float64(p.Done) / el.Seconds()
	rest := "计算中"
	if pps > 0 && p.Total > p.Done {
		rem := time.Duration(float64(p.Total-p.Done)/pps) * time.Second
		if rem > 24*time.Hour {
			rem = 24 * time.Hour // 早期样本少时 ETA 抖动极大，封顶一天
		}
		rest = rem.Round(time.Second).String()
	} else if p.Total > 0 && p.Done >= p.Total {
		rest = "0s"
	}
	return fmt.Sprintf("[扫描] 进行中 %d%%（%d/%d 探针，已用 %s，剩余 %s）｜%.0f 探针/秒｜开放 %d 个，识别 %d 个",
		pct, p.Done, p.Total, el.Round(time.Second), rest, pps, p.Open, p.Ident)
}

// ReportDone 完成行的输入。
type ReportDone struct {
	Probes, Total int64
	Elapsed       time.Duration
	Open, Ident   int64
}

// FormatDoneLine 完成行。
//
// 示例：`[扫描] 完成 65535/65535 探针，耗时 26s，平均 2520 探针/秒，开放 6 个，识别 6 个`
func FormatDoneLine(d ReportDone) string {
	el := d.Elapsed
	if el <= 0 {
		el = time.Millisecond
	}
	pps := float64(d.Probes) / el.Seconds()
	return fmt.Sprintf("[扫描] 完成 %d/%d 探针，耗时 %s，平均 %.0f 探针/秒，开放 %d 个，识别 %d 个",
		d.Probes, d.Total, el.Round(time.Second), pps, d.Open, d.Ident)
}
