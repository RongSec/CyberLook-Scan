package portscan

// 透明代理 / 中间件的识别
//
// 现象（实测）：对 192.0.2.1（RFC5737 保留地址，真实网络里不可能存在）连 80 端口，
// 1ms 就"连接成功"，但之后一个字节都不返回；连 65001 端口则正常超时。
// 说明链路上有设备在做 SYN 代理/透明 HTTP(S) 代理，替任意不存在的地址完成了握手。
//
// 后果：connect 扫描会把这类端口判成"全网开放"。实测一张 /18 因此报出 8800 台
// "存活"主机，其中 96% 连一个开放端口都没有 —— 这不是假阴性，是纯粹的假阳性，
// 比漏报更坏：它把台账污染得没法用。
//
// 对策：用保留地址做探针，任何"能连上"的端口都判定为被中间件接管，
// 这类端口不参与存活判定，也不参与端口扫描（或至少标出来）。

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"
)

// interceptCanaries 保留地址（TEST-NET-1/2）。正常网络里它们不可路由，
// 连上去必然超时或 EHOSTUNREACH；"连上了"就只能是链路上有设备替它应答。
var interceptCanaries = []string{"192.0.2.1", "198.51.100.1"}

// DetectInterceptedPorts 检测哪些端口被中间件接管。
// 返回 (被接管的端口, 是否检测到接管)。检测本身失败时返回 (nil,false)，按"没有接管"处理。
//
// 每个端口最多 2 次 dial（两个 canary），timeout 建议 300~500ms。
func DetectInterceptedPorts(ctx context.Context, ports []int, timeout time.Duration) ([]int, bool) {
	if len(ports) == 0 {
		return nil, false
	}
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}
	var (
		mu       sync.Mutex
		bad      []int
		anyTried bool
	)
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for _, p := range ports {
		for _, host := range interceptCanaries {
			wg.Add(1)
			sem <- struct{}{}
			go func(port int, addr string) {
				defer wg.Done()
				defer func() { <-sem }()
				d := net.Dialer{Timeout: timeout}
				c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
				mu.Lock()
				anyTried = true
				mu.Unlock()
				if err != nil {
					return
				}
				_ = c.Close()
				mu.Lock()
				for _, v := range bad {
					if v == port {
						mu.Unlock()
						return
					}
				}
				bad = append(bad, port)
				mu.Unlock()
			}(p, host)
		}
	}
	wg.Wait()
	return bad, anyTried && len(bad) > 0
}

// portInSet 判断端口是否在集合里（集合很小，线性扫足够）。
func portInSet(set []int, p int) bool {
	for _, v := range set {
		if v == p {
			return true
		}
	}
	return false
}

// filterPorts 去掉被中间件接管的端口。
func filterPorts(ports []int, intercepted []int) []int {
	if len(intercepted) == 0 {
		return ports
	}
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if !portInSet(intercepted, p) {
			out = append(out, p)
		}
	}
	return out
}
