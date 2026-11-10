package portscan

// 存活探测（host discovery）
//
// 实现取舍：
//   - 只用 connect() 探 TCP 常用端口，**不做 ICMP / raw socket**：
//     Windows 下 raw socket 需要管理员权限，且行为不稳（没权限时整条链路直接失效）。
//     TCP connect 无特权要求、跨平台一致，还能顺带把"哪个端口开着"一起拿到。
//   - 任一端口连上即判定存活，并做 best-effort 短路：已判定存活的 IP，
//     其剩余端口的探针在投递与执行两侧都会跳过，不浪费探针。
//   - 短超时（默认 400ms）：存活探测的目的是快速筛掉死主机，不是精确端口枚举；
//     过滤型防火墙下的静默丢弃由后续完整端口扫描兜底。

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultAlivePorts 存活探测的常用端口集（覆盖 Web / SSH / SMB / RDP / RPC / MySQL）
var DefaultAlivePorts = []int{80, 443, 22, 445, 3389, 8080, 8443, 135, 139, 3306}

// DefaultAliveTimeout 存活探测单端口默认超时
const DefaultAliveTimeout = 400 * time.Millisecond

// AliveHost 一个存活主机及其命中的端口
type AliveHost struct {
	IP        string `json:"ip"`
	OpenPorts []int  `json:"openPorts"`
}

// AliveStats 存活探测汇总
type AliveStats struct {
	Hosts   int           // 待探测主机数
	Ports   int           // 每台主机探测的端口数
	Probes  int64         // 实际发出的探针数
	Skipped int64         // 因已判定存活而短路跳过的探针数
	Alive   int           // 存活主机数
	Elapsed time.Duration // 总耗时
}

// aliveHit 单台主机的命中端口收集（每台一个，写入方自带互斥，读取发生在 wg.Wait 之后）
type aliveHit struct {
	mu sync.Mutex
	v  []int
}

func (h *aliveHit) add(port int) {
	h.mu.Lock()
	h.v = append(h.v, port)
	h.mu.Unlock()
}

func (h *aliveHit) sorted() []int {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := append([]int(nil), h.v...)
	sort.Ints(out)
	return out
}

// AliveProbe 对 ips 做 TCP connect 存活探测，返回存活主机（按 IP 排序）。
// ports 为空时用 DefaultAlivePorts；timeout<=0 时用 DefaultAliveTimeout；
// concurrency<=0 时用 512。
func AliveProbe(ctx context.Context, ips []string, ports []int, concurrency int, timeout time.Duration) []AliveHost {
	hosts, _ := AliveProbeStats(ctx, ips, ports, concurrency, timeout)
	return hosts
}

// AliveProbeStats 同 AliveProbe，但额外返回汇总统计（探测数 / 存活数 / 耗时）。
func AliveProbeStats(ctx context.Context, ips []string, ports []int, concurrency int, timeout time.Duration) ([]AliveHost, AliveStats) {
	st := AliveStats{Hosts: len(ips), Ports: len(ports)}
	if len(ips) == 0 {
		return nil, st
	}
	if len(ports) == 0 {
		ports = DefaultAlivePorts
		st.Ports = len(ports)
	}
	if timeout <= 0 {
		timeout = DefaultAliveTimeout
	}
	if concurrency <= 0 {
		concurrency = 512
	}

	type job struct {
		ipIdx int
		port  int
	}

	// alive[i] == 1 表示第 i 个 IP 已判定存活（atomic 读写，best-effort 短路依据）
	alive := make([]int32, len(ips))
	hits := make([]aliveHit, len(ips))
	var probes, skipped int64

	start := time.Now()
	jobs := make(chan job, minInt(concurrency*2, 8192))
	var wg sync.WaitGroup
	workerCount := minInt(concurrency, len(ips)*len(ports))
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				// 短路：该 IP 已判定存活，剩余端口不必再探
				if atomic.LoadInt32(&alive[j.ipIdx]) == 1 {
					atomic.AddInt64(&skipped, 1)
					continue
				}
				addr := net.JoinHostPort(ips[j.ipIdx], strconv.Itoa(j.port))
				conn, err := d.DialContext(ctx, "tcp", addr)
				atomic.AddInt64(&probes, 1)
				if err != nil {
					continue
				}
				_ = conn.Close()
				hits[j.ipIdx].add(j.port)
				atomic.StoreInt32(&alive[j.ipIdx], 1)
			}
		}()
	}

dispatch:
	for i := range ips {
		for _, port := range ports {
			if atomic.LoadInt32(&alive[i]) == 1 {
				atomic.AddInt64(&skipped, 1)
				continue
			}
			select {
			case jobs <- job{ipIdx: i, port: port}:
			case <-ctx.Done():
				break dispatch
			}
		}
	}
	close(jobs)
	wg.Wait()

	out := make([]AliveHost, 0, len(ips))
	for i, ip := range ips {
		if atomic.LoadInt32(&alive[i]) != 1 {
			continue
		}
		ps := hits[i].sorted()
		if ps == nil {
			ps = []int{}
		}
		out = append(out, AliveHost{IP: ip, OpenPorts: ps})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].IP < out[b].IP })

	st.Probes = atomic.LoadInt64(&probes)
	st.Skipped = atomic.LoadInt64(&skipped)
	st.Alive = len(out)
	st.Elapsed = time.Since(start)
	return out, st
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
