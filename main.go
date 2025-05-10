package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const statsFile = "stats.json"

var statsMutex sync.RWMutex
var stats = make(map[string]int)

func loadStats(filename string) (map[string]int, error) {
	st := make(map[string]int)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return st, nil
}

func saveStats(filename string, st map[string]int) error {
	statsMutex.RLock()
	defer statsMutex.RUnlock()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, data, 0644)
}

func main() {
	iface := flag.String("i", "eth0", "网络接口")
	resetStats := flag.Bool("reset", false, "每分钟是否清除统计")
	flag.Parse()

	loadedStats, err := loadStats(statsFile)
	if err != nil {
		log.Fatalf("加载统计数据失败: %v", err)
	}
	statsMutex.Lock()
	stats = loadedStats
	statsMutex.Unlock()
	log.Printf("已加载 %d 条历史记录", len(stats))

	handle, err := pcap.OpenLive(*iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("打开接口失败: %v", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp or udp"); err != nil {
		log.Fatalf("设置过滤器失败: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	go func() {
		for t := range ticker.C {
			statsMutex.RLock()
			fmt.Printf("\n统计更新时间：%s\n", t.Format("2006-01-02 15:04:05"))
			for key, bytes := range stats {
				fmt.Printf("%s: %d Bytes\n", key, bytes)
			}
			fmt.Println("-----------------------------------------------")
			statsMutex.RUnlock()

			if err := saveStats(statsFile, stats); err != nil {
				log.Printf("保存统计数据失败: %v", err)
			} else {
				log.Printf("统计数据已保存到 %s", statsFile)
			}

			if *resetStats {
				statsMutex.Lock()
				stats = make(map[string]int)
				statsMutex.Unlock()
			}
		}
	}()

	for packet := range packetSource.Packets() {
		packetTime := packet.Metadata().CaptureInfo.Timestamp
		yearMonth := packetTime.Format("2006-01")

		var dstIP string
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			dstIP = ip4Layer.(*layers.IPv4).DstIP.String()
		} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			dstIP = ip6Layer.(*layers.IPv6).DstIP.String()
		} else {
			continue
		}

		var dstPort string
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			dstPort = fmt.Sprintf("%d", tcpLayer.(*layers.TCP).DstPort)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			dstPort = fmt.Sprintf("%d", udpLayer.(*layers.UDP).DstPort)
		}
		if dstPort == "" {
			continue
		}

		key := fmt.Sprintf("%s-%s:%s", yearMonth, dstIP, dstPort)
		length := packet.Metadata().CaptureInfo.Length

		statsMutex.Lock()
		stats[key] += length
		statsMutex.Unlock()
	}
}
