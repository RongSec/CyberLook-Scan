// 这个嵌套 go.mod 的唯一作用是：把 data/ 排除出根模块的 zip。
//
// 背景：data/fingerprint 里有约 11MB 指纹规则，是 CLI 运行时从磁盘读取的
// （没有任何 go:embed 引用）。但它会被打进模块 zip，导致代理拉取
// github.com/RongSec/CyberLook-Scan 时反复失败（goproxy.cn 对超大 zip 返回
// stream error INTERNAL_ERROR），平台一侧根本 go get 不下来。
//
// Go 的规则：子目录里若有自己的 go.mod，就不会被父模块包含。
// 所以这里放一个"空模块"声明即可，不参与任何编译。
module github.com/RongSec/CyberLook-Scan/data

go 1.26.0
