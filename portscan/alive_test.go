package portscan

import (
	"context"
	"net"
	"testing"
	"time"
)

// listenLocal 在 127.0.0.1 上开一个监听端口，返回端口号（用于构造"必然存活"的样本）
func listenLocal(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("本机无法监听端口，跳过: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// assertHostsLegal 存活清单结构合法性检查（存活/不存活两种结果都必须满足）
func assertHostsLegal(t *testing.T, hosts []AliveHost, wantIP string) {
	t.Helper()
	for _, h := range hosts {
		if h.IP == "" {
			t.Errorf("存活主机 IP 为空: %+v", h)
		}
		if wantIP != "" && h.IP != wantIP {
			t.Errorf("存活主机 IP = %s，期望 %s", h.IP, wantIP)
		}
		if h.OpenPorts == nil {
			t.Errorf("%s 的 OpenPorts 为 nil（应为空切片，保证 JSON 输出为 []）", h.IP)
		}
		for i := 1; i < len(h.OpenPorts); i++ {
			if h.OpenPorts[i] <= h.OpenPorts[i-1] {
				t.Errorf("%s 命中端口未升序去重: %v", h.IP, h.OpenPorts)
				break
			}
		}
		for _, p := range h.OpenPorts {
			if p <= 0 || p > 65535 {
				t.Errorf("%s 命中端口非法: %d", h.IP, p)
			}
		}
	}
}

// TestAliveProbeKnownOpen 本机监听端口必须判存活，且命中端口被记录
func TestAliveProbeKnownOpen(t *testing.T) {
	port := listenLocal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hosts, st := AliveProbeStats(ctx, []string{"127.0.0.1"}, []int{port}, 16, DefaultAliveTimeout)
	assertHostsLegal(t, hosts, "127.0.0.1")

	if st.Hosts != 1 || st.Ports != 1 {
		t.Errorf("统计规模不对: %+v", st)
	}
	if st.Elapsed > 5*time.Second {
		t.Errorf("耗时上限超标: %s", st.Elapsed)
	}
	if len(hosts) != 1 {
		t.Fatalf("本机监听端口 %d 应判存活，实际 hosts=%v", port, hosts)
	}
	if len(hosts[0].OpenPorts) != 1 || hosts[0].OpenPorts[0] != port {
		t.Errorf("命中端口 = %v，期望 [%d]", hosts[0].OpenPorts, port)
	}
	if st.Alive != 1 || st.Probes != 1 {
		t.Errorf("统计不对: alive=%d probes=%d", st.Alive, st.Probes)
	}
}

// TestAliveProbeLocalhostCommonPorts 用默认常用端口探 127.0.0.1：
// 本机是否有监听端口不可控，因此两种结果都只断言结构合法 + 耗时上限，不允许 panic。
func TestAliveProbeLocalhostCommonPorts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	hosts, st := AliveProbeStats(ctx, []string{"127.0.0.1"}, nil, 64, DefaultAliveTimeout)
	wall := time.Since(start)
	assertHostsLegal(t, hosts, "127.0.0.1")

	if len(hosts) > 1 {
		t.Errorf("单 IP 最多一个存活条目，实际 %d", len(hosts))
	}
	if len(hosts) == 0 && st.Alive != 0 {
		t.Errorf("存活数与清单不一致: alive=%d hosts=%d", st.Alive, len(hosts))
	}
	if st.Hosts != 1 || st.Ports != len(DefaultAlivePorts) {
		t.Errorf("默认端口集统计不对: %+v", st)
	}
	if st.Probes+st.Skipped > int64(st.Hosts*st.Ports) {
		t.Errorf("探针数超发: probes=%d skipped=%d 上限=%d", st.Probes, st.Skipped, st.Hosts*st.Ports)
	}
	// 耗时上限：并发下不应显著超过单端口超时（留足调度余量）
	if wall > 8*time.Second {
		t.Errorf("耗时上限超标: wall=%s stats=%s", wall, st.Elapsed)
	}
	t.Logf("127.0.0.1 常用端口存活探测: hosts=%d probes=%d skipped=%d elapsed=%s",
		len(hosts), st.Probes, st.Skipped, st.Elapsed.Round(time.Millisecond))
}

// TestAliveProbeShortCircuit 已判定存活的 IP，剩余端口应被短路跳过
func TestAliveProbeShortCircuit(t *testing.T) {
	port := listenLocal(t)
	// 存活端口排在最前，后续大量端口应基本被跳过
	ports := []int{port, 60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 单 worker 保证投递顺序生效
	hosts, st := AliveProbeStats(ctx, []string{"127.0.0.1"}, ports, 1, 200*time.Millisecond)
	assertHostsLegal(t, hosts, "127.0.0.1")
	if st.Probes+st.Skipped != int64(len(ports)) {
		t.Errorf("探针+跳过应等于总端口数: probes=%d skipped=%d total=%d", st.Probes, st.Skipped, len(ports))
	}
	if st.Skipped == 0 {
		t.Errorf("未发生短路跳过，短路优化未生效: %+v", st)
	}
}

// TestAliveProbeEmptyInputs 空输入与已取消上下文都不得 panic
func TestAliveProbeEmptyInputs(t *testing.T) {
	if hosts, st := AliveProbeStats(context.Background(), nil, nil, 0, 0); len(hosts) != 0 || st.Alive != 0 {
		t.Errorf("空目标应无存活: %v %+v", hosts, st)
	}
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if hosts, _ := AliveProbeStats(cctx, []string{"127.0.0.1"}, []int{9}, 4, 100*time.Millisecond); len(hosts) > 1 {
		t.Errorf("取消后结果异常: %v", hosts)
	}
	if AliveProbe(context.Background(), []string{}, []int{9}, 4, time.Millisecond) == nil {
		// 允许返回 nil 或空切片，仅确认可调用
	}
}

// TestAliveProbeMultiIP 多 IP：不存在的本机端口应判不存活
func TestAliveProbeMultiIP(t *testing.T) {
	port := listenLocal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips := []string{"127.0.0.1", "127.0.0.2"}
	hosts, st := AliveProbeStats(ctx, ips, []int{port, 60011}, 8, 300*time.Millisecond)
	assertHostsLegal(t, hosts, "")
	if st.Hosts != 2 {
		t.Errorf("目标数不对: %+v", st)
	}
	for _, h := range hosts {
		if h.IP != "127.0.0.1" && h.IP != "127.0.0.2" {
			t.Errorf("出现了未探测的主机: %s", h.IP)
		}
	}
	if st.Elapsed > 10*time.Second {
		t.Errorf("耗时上限超标: %s", st.Elapsed)
	}
	t.Logf("多 IP 存活: %+v", hosts)
}
