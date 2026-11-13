package portscan

// 存活探测（host discovery）—— ICMP + TCP 两阶段，平台与 CLI 共用这一份实现
//
// 判定链：
//   - 阶段 1 ICMP Echo（非特权 udp4；Linux 只要 net.ipv4.ping_group_range 允许即可，
//     否则自动跳过整个阶段，不影响使用）。Echo Reply → 存活；
//     Destination Unreachable → 明确判死，TCP 阶段跳过这台（省时间）。
//   - 阶段 2 TCP connect 到常用端口。连上（SYN-ACK）或被拒绝（RST）都算存活
//     —— RST 说明主机回了包，只是端口关着。
//
// 为什么必须两层：目标把 SYN 静默丢弃（防火墙默认 DROP）时，纯 TCP 会把这台
// **活着但端口被过滤**的机器判死；反过来只做 ICMP 会漏掉不响应 ping 的机器。
// 实测某 /16：605 台存活里 312 台五个常用端口全不通（纯 TCP 会全漏），
// 另有 310 台不响应 ICMP（纯 ICMP 会全漏）。两层互补，缺一不可。
//
// 为什么要对 ICMP 已判活的主机仍跑 TCP：调用方（CLI）需要 OpenPorts，
// 而且端口真值由 TCP 阶段给出，ICMP 只负责"这台还活着"。只有 ICMP 明确不可达的才跳过。
//
// 平台（CyberLook）与本 CLI 都调用这里的 DiscoverHosts，行为与性能天然一致。

import (
	"context"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// DefaultAlivePorts 存活探测的常用端口集。
// 覆盖 Web(80/443/8080/8443/9443)、运维(22)、Windows(445/135/139/3389)、
// 数据库(3306/6379/1433/5432/27017) 与中间件(9200)。
//
// 为什么不是只有 80/443/22：只有单一服务的机器（只开 6379、只开 9200）也要能判出来。
// 实测某 /16：605 台存活主机里 **312 台（52%）** 五个常见端口一个都不通，
// 端口集太窄会把这些整台漏掉。
//
// 注意：本 CLI 只做 TCP 判定（保持零第三方依赖、任意系统免权限可跑）。
// 服务端平台的存活探测是 ICMP + TCP 两层，覆盖面更广；CLI 这边窄一些是刻意的取舍。
var DefaultAlivePorts = []int{
	80, 443, 22, 445, 135, 139, 3389, 8080, 8443, 9443,
	3306, 6379, 1433, 5432, 27017, 9200,
}

// DefaultAliveTimeout 存活探测单端口默认超时
const DefaultAliveTimeout = 400 * time.Millisecond

// AliveHost 一个存活主机及其命中的端口
type AliveHost struct {
	IP        string `json:"ip"`
	OpenPorts []int  `json:"openPorts"`
}

// AliveStats 存活探测汇总
type AliveStats struct {
	Hosts    int           // 待探测主机数
	Ports    int           // 每台主机探测的端口数
	Probes   int64         // 实际发出的 TCP 探针数
	Skipped  int64         // 因已判定存活而短路跳过的探针数
	Alive    int           // 存活主机数
	ByICMP   int           // 其中 ICMP 判活的台数
	ByTCP    int           // 其中 TCP 单独判活的台数
	Unreach  int           // ICMP 明确不可达的台数
	ICMPSkip bool          // ICMP 阶段是否被跳过（无权限/非 Linux/关闭）
	Elapsed  time.Duration // 总耗时
}

// AliveOptions 存活探测参数（零值即可用）。
type AliveOptions struct {
	Ports       []int         // TCP 阶段端口；空 = DefaultAlivePorts
	Concurrency int           // 并发主机数；0 = 512
	TCPTimeout  time.Duration // 单端口超时；0 = 400ms
	ICMP        bool          // 是否启用 ICMP 阶段（无权限时自动跳过，不报错）
	// SkipTCPIfAlive 被 ICMP 判活的主机不再跑 TCP。
	// 只关心"活着/没活着"的调用方（平台）打开它，能省掉一轮无用探针；
	// 需要 OpenPorts 真值的调用方（CLI）必须关闭，否则端口列表是空的。
	SkipTCPIfAlive bool
	// OnProgress 进度回调（done=已处理主机数，alive=当前存活数，均为 0..Hosts 内单调递增）；
	// 返回 false 中止探测。回调会被节流（约每 0.7s 一次 + 每个 ICMP 批次一次），
	// 可以直接在里面写库/推 SSE。
	OnProgress func(done, alive int) bool
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

// AliveProbeStats 同 AliveProbe，但额外返回汇总统计。
func AliveProbeStats(ctx context.Context, ips []string, ports []int, concurrency int, timeout time.Duration) ([]AliveHost, AliveStats) {
	return DiscoverHosts(ctx, ips, AliveOptions{
		Ports: ports, Concurrency: concurrency, TCPTimeout: timeout, ICMP: true,
	})
}

// DiscoverHosts 两阶段存活探测（ICMP Echo → TCP connect），平台与 CLI 共用。
func DiscoverHosts(ctx context.Context, ips []string, opt AliveOptions) ([]AliveHost, AliveStats) {
	ports := opt.Ports
	if len(ports) == 0 {
		ports = DefaultAlivePorts
	}
	timeout := opt.TCPTimeout
	if timeout <= 0 {
		timeout = DefaultAliveTimeout
	}
	concurrency := opt.Concurrency
	if concurrency <= 0 {
		concurrency = 512
	}
	onProgress := opt.OnProgress
	if onProgress == nil {
		onProgress = func(int, int) bool { return true }
	}

	st := AliveStats{Hosts: len(ips), Ports: len(ports)}
	if len(ips) == 0 {
		return nil, st
	}
	start := time.Now()
	n := len(ips)

	// ── 进度：ICMP 与 TCP 各算一遍"主机数"，归一化到 0..n，各占一半 ──
	// 两遍都处理全部主机，进度条从 0 走到 n（50% 处进 TCP 阶段）。
	// 为什么这样归一化：ICMP 阶段也可能占掉可观时间（大网段几万 IP），
	// 如果第二遍才从 0 开始数，进度条会先到 100% 再跳回 0；
	// 反过来只报 ICMP 阶段的原始台数，进度会在 50% 之前一直贴着 0。
	var icmpDone, tcpDone, aliveNum int64
	report := func() bool {
		d := (int(atomic.LoadInt64(&icmpDone)) + int(atomic.LoadInt64(&tcpDone))) / 2
		if d > n {
			d = n
		}
		a := int(atomic.LoadInt64(&aliveNum))
		if a > n {
			a = n
		}
		return onProgress(d, a)
	}

	// ===== 阶段 1：ICMP =====
	icmpAlive := map[string]bool{}
	unreach := map[string]bool{}
	icmpSkip := true
	if opt.ICMP {
		icmpAlive, unreach, icmpSkip = icmpSweep(ctx, ips, func(done, alive int) bool {
			atomic.StoreInt64(&icmpDone, int64(done))
			atomic.StoreInt64(&aliveNum, int64(alive))
			return report()
		})
	}
	atomic.StoreInt64(&icmpDone, int64(n))
	if icmpSkip {
		// ICMP 不可用（无权限/平台不支持）：整段算 0 成本，进度由 TCP 阶段一肩挑
		atomic.StoreInt64(&icmpDone, int64(n))
	}

	// ===== 阶段 2：TCP（跳过 ICMP 明确不可达的；可选跳过 ICMP 已判活的）=====
	skip := unreach
	if opt.SkipTCPIfAlive {
		skip = make(map[string]bool, len(unreach)+len(icmpAlive))
		for ip := range unreach {
			skip[ip] = true
		}
		for ip := range icmpAlive {
			skip[ip] = true
		}
		// 这些主机已经处理完了，先记进第二遍的完成数，进度才不会原地不动
		atomic.StoreInt64(&tcpDone, int64(len(icmpAlive)))
	}
	targets := make([]string, 0, len(ips))
	for _, ip := range ips {
		if skip[ip] {
			continue
		}
		targets = append(targets, ip)
	}

	type job struct {
		ipIdx int
		port  int
	}
	tcpAlive := make([]int32, len(targets))
	// finished 保证每台主机在进度里只计一次（判活与"端口探完"是两条路径）
	finished := make([]int32, len(targets))
	remaining := make([]int32, len(targets))
	for i := range targets {
		remaining[i] = int32(len(ports))
	}
	hits := make([]aliveHit, len(targets))
	var probes, skipped int64

	// finishHost 每台主机只认第一次：CAS 失败说明已经计过数了。
	// aliveNum 的累加必须挂在这个闸门上 —— 两个端口并发连通同一台主机时，
	// 各自都会走到"判活"分支，不设闸门就会把这台机器算两次
	// （实测 /16 上进度里报 1703 台存活，实际只有 977 台）。
	finishHost := func(i int, alive bool) {
		if atomic.CompareAndSwapInt32(&finished[i], 0, 1) {
			atomic.AddInt64(&tcpDone, 1)
			if alive {
				atomic.AddInt64(&aliveNum, 1)
			}
		}
	}

	jobs := make(chan job, minInt(concurrency*2, 8192))
	var wg sync.WaitGroup
	workerCount := minInt(concurrency, len(targets)*len(ports))
	if workerCount < 1 {
		workerCount = 1
	}
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				if atomic.LoadInt32(&tcpAlive[j.ipIdx]) == 1 {
					atomic.AddInt64(&skipped, 1) // 短路：这台已判活，剩余端口不再探
					continue
				}
				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(targets[j.ipIdx], strconv.Itoa(j.port)))
				atomic.AddInt64(&probes, 1)
				if err == nil {
					_ = conn.Close()
					hits[j.ipIdx].add(j.port)
					atomic.StoreInt32(&tcpAlive[j.ipIdx], 1)
					finishHost(j.ipIdx, true)
					continue
				}
				if atomic.AddInt32(&remaining[j.ipIdx], -1) == 0 {
					finishHost(j.ipIdx, false)
				}
			}
		}()
	}

	// 周期上报：TCP 阶段是主要耗时，没有它界面就只有"探测中"三个字
	repCtx, stopRep := context.WithCancel(ctx)
	defer stopRep()
	repDone := make(chan struct{})
	go func() {
		defer close(repDone)
		t := time.NewTicker(700 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-repCtx.Done():
				return
			case <-t.C:
				if !report() {
					stopRep()
					return
				}
			}
		}
	}()

dispatch:
	for i := range targets {
		for pi, port := range ports {
			if atomic.LoadInt32(&tcpAlive[i]) == 1 {
				// 这台已判活：剩下的端口一个都不用发，全部记入跳过（统计要能算平）
				atomic.AddInt64(&skipped, int64(len(ports)-pi))
				break
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
	stopRep()
	<-repDone

	// ===== 合并：ICMP 或 TCP 任一判活即存活 =====
	aliveIdx := make(map[string]int, len(targets))
	for i, ip := range targets {
		aliveIdx[ip] = i
	}
	out := make([]AliveHost, 0, len(ips)/4)
	for _, ip := range ips {
		_, byTCP := aliveIdx[ip]
		byTCP = byTCP && atomic.LoadInt32(&tcpAlive[aliveIdx[ip]]) == 1
		if icmpAlive[ip] || byTCP {
			ps := []int{}
			if byTCP {
				if v := hits[aliveIdx[ip]].sorted(); v != nil {
					ps = v
				}
			}
			out = append(out, AliveHost{IP: ip, OpenPorts: ps})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].IP < out[b].IP })

	st.Probes = atomic.LoadInt64(&probes)
	st.Skipped = atomic.LoadInt64(&skipped)
	st.Alive = len(out)
	st.ByICMP = countTrue(icmpAlive, ips)
	for _, ip := range targets {
		if atomic.LoadInt32(&tcpAlive[aliveIdx[ip]]) == 1 {
			st.ByTCP++
		}
	}
	st.Unreach = len(unreach)
	st.ICMPSkip = icmpSkip
	st.Elapsed = time.Since(start)

	// 收尾：把进度顶到 100%（前面按两遍各半归一化，末尾补齐误差）
	atomic.StoreInt64(&icmpDone, int64(n))
	atomic.StoreInt64(&tcpDone, int64(n))
	atomic.StoreInt64(&aliveNum, int64(len(out)))
	_ = report()
	return out, st
}

// ===== ICMP 阶段 =====

// icmpSweep 批量发 Echo 并收集回包。返回 (存活, 明确不可达, 是否跳过)。
// onBatch(已处理台数, 存活台数) 每批回调一次，返回 false 中止。
//
// 实现：一个 socket 发全部、一个 goroutine 收全部，按源 IP 归集 ——
// 不做逐 IP 同步等待（那样 9 万个 IP 就要等 9 万次超时）。
// ICMP 不可用（无权限/平台不支持）时返回 (nil,nil,true)，退化为纯 TCP。
func icmpSweep(ctx context.Context, ips []string, onBatch func(done, alive int) bool) (map[string]bool, map[string]bool, bool) {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, nil, true
	}
	defer conn.Close()

	alive := make(map[string]bool, len(ips)/4)
	unreach := make(map[string]bool, 64)
	var mu sync.Mutex

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			addr, ok := peer.(*net.UDPAddr)
			if !ok {
				continue
			}
			msg, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				continue
			}
			ip := addr.IP.String()
			switch msg.Type {
			case ipv4.ICMPTypeEchoReply:
				mu.Lock()
				alive[ip] = true
				mu.Unlock()
			case ipv4.ICMPTypeDestinationUnreachable:
				mu.Lock()
				if !alive[ip] {
					unreach[ip] = true
				}
				mu.Unlock()
			}
		}
	}()

	id := os.Getpid() & 0xffff
	seq := 0
	for i := 0; i < len(ips); i++ {
		if ctx.Err() != nil {
			break
		}
		seq++
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{ID: id, Seq: seq & 0xffff, Data: []byte("alive-probe")},
		}
		b, err := msg.Marshal(nil)
		if err != nil {
			continue
		}
		dst := &net.UDPAddr{IP: net.ParseIP(ips[i])}
		if dst.IP == nil {
			continue
		}
		if _, err := conn.WriteTo(b, dst); err != nil {
			mu.Lock()
			unreach[ips[i]] = true
			mu.Unlock()
		}
		if i%aliveICMPBatch == aliveICMPBatch-1 {
			time.Sleep(10 * time.Millisecond)
			mu.Lock()
			done, hit := i+1, len(alive)
			mu.Unlock()
			if !onBatch(done, hit) {
				break // 调用方要求中止：停止发包，已发的等回包
			}
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(aliveICMPWait))
	<-readDone
	return alive, unreach, false
}

const (
	aliveICMPBatch = 1000
	aliveICMPWait  = 1200 * time.Millisecond
)

// countTrue 统计 map 中有多少个 key 在 ips 里（避免把不在本次目标里的回包算进来）。
func countTrue(m map[string]bool, ips []string) int {
	if len(m) == 0 {
		return 0
	}
	n := 0
	for _, ip := range ips {
		if m[ip] {
			n++
		}
	}
	return n
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
