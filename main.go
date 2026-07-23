// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type options struct {
	Protocol           string
	ListenAddrStr      string
	TargetAddr4Str     string
	TargetAddr6Str     string
	ListenAddr         netip.AddrPort
	TargetAddr4        netip.AddrPort
	TargetAddr6        netip.AddrPort
	Mark               int
	Table              int
	AutoRules          bool
	Verbose            int
	allowedSubnetsPath string
	AllowedSubnets     []*net.IPNet
	Listeners          int
	Logger             *slog.Logger
	udpCloseAfter      int
	UDPCloseAfter      time.Duration
}

var Opts options

func init() {
	flag.StringVar(&Opts.Protocol, "p", "tcp", "Protocol that will be proxied: tcp, udp, frpudp")
	flag.StringVar(&Opts.ListenAddrStr, "l", "0.0.0.0:8443", "Address the proxy listens on")
	flag.StringVar(&Opts.TargetAddr4Str, "4", "127.0.0.1:443", "Address to which IPv4 traffic will be forwarded to")
	flag.StringVar(&Opts.TargetAddr6Str, "6", "[::1]:443", "Address to which IPv6 traffic will be forwarded to")
	flag.IntVar(&Opts.Mark, "mark", 0, "The mark that will be set on outbound packets")
	flag.IntVar(&Opts.Table, "table", 123, "The routing table that will be used for outbound packets")
	flag.BoolVar(&Opts.AutoRules, "a", false, "Automatically setup ip rules and routing tables")
	flag.IntVar(&Opts.Verbose, "v", 0, `0 - no logging of individual connections
1 - log errors occurring in individual connections
2 - log all state changes of individual connections`)
	flag.StringVar(&Opts.allowedSubnetsPath, "allowed-subnets", "",
		"Path to a file that contains allowed subnets of the proxy servers")
	flag.IntVar(&Opts.Listeners, "listeners", 1,
		"Number of listener sockets that will be opened for the listen address (Linux 3.9+)")
	flag.IntVar(&Opts.udpCloseAfter, "close-after", 60, "Number of seconds after which UDP socket will be cleaned up")
}

func listen(listenerNum int, errors chan<- error) {
	logger := Opts.Logger.With(slog.Int("listenerNum", listenerNum),
		slog.String("protocol", Opts.Protocol), slog.String("listenAdr", Opts.ListenAddr.String()))

	listenConfig := net.ListenConfig{}
	if Opts.Listeners > 1 {
		listenConfig.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				soReusePort := 15
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1); err != nil {
					logger.Warn("failed to set SO_REUSEPORT - only one listener setup will succeed")
				}
			})
		}
	}

	if Opts.Protocol == "tcp" {
		if Opts.AutoRules {
			setupIPRules()
		}
		TCPListen(&listenConfig, logger, errors)
	} else if Opts.Protocol == "udp" {
		if Opts.AutoRules {
			setupIPRules()
		}
		UDPListen(&listenConfig, logger, errors)
	} else {
		if Opts.AutoRules {
			setupIPRules()
		}
		FRPUDPListen(&listenConfig, logger, errors)
	}
}

var setupOnce sync.Once

func setupIPRules() {
	setupOnce.Do(func() {
		Opts.Logger.Info("setting up IP rules and routing tables")
		tableStr := strconv.Itoa(Opts.Table)

		// 1. 确保路由表 local 路由存在
		// IPv4 local route
		runCmdIgnoreExists("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", tableStr)
		// IPv6 local route
		runCmdIgnoreExists("ip", "-6", "route", "add", "local", "::/0", "dev", "lo", "table", tableStr)

		if Opts.Mark > 0 {
			markStr := strconv.Itoa(Opts.Mark)
			Opts.Logger.Info("mark is set, configuring mark-based routing and iptables", slog.Int("mark", Opts.Mark))

			// IPv4 mark rule
			runCmdIgnoreExists("ip", "rule", "add", "fwmark", markStr, "table", tableStr)
			// IPv6 mark rule
			runCmdIgnoreExists("ip", "-6", "rule", "add", "fwmark", markStr, "table", tableStr)

			proto := "tcp"
			if Opts.Protocol == "udp" || Opts.Protocol == "frpudp" {
				proto = "udp"
			}
			port4Str := strconv.Itoa(int(Opts.TargetAddr4.Port()))
			port6Str := strconv.Itoa(int(Opts.TargetAddr6.Port()))

			// iptables rules for IPv4
			setupIptablesRule("iptables", "-t", "mangle", "-C", "OUTPUT", "-p", proto, "--sport", port4Str, "-j", "MARK", "--set-mark", markStr)

			// ip6tables rules for IPv6
			setupIptablesRule("ip6tables", "-t", "mangle", "-C", "OUTPUT", "-p", proto, "--sport", port6Str, "-j", "MARK", "--set-mark", markStr)
		} else {
			Opts.Logger.Info("no mark set, configuring default source-IP-based routing")

			// IPv4 source-IP-based rule
			runCmdIgnoreExists("ip", "rule", "add", "from", "127.0.0.1/8", "iif", "lo", "table", tableStr)
			// IPv6 source-IP-based rule
			runCmdIgnoreExists("ip", "-6", "rule", "add", "from", "::1/128", "iif", "lo", "table", tableStr)
		}
	})
}

func runCmdIgnoreExists(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	output, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(output)
		outLower := strings.ToLower(outStr)
		if strings.Contains(outLower, "file exists") ||
			strings.Contains(outLower, "already exists") ||
			strings.Contains(outLower, "not supported") ||
			strings.Contains(outLower, "unknown family") {
			// 规则或路由已存在，或者系统不支持该协议族，忽略错误
			return
		}
		Opts.Logger.Warn("failed to run command", slog.String("cmd", name+" "+strings.Join(args, " ")), slog.String("error", err.Error()), slog.String("output", outStr))
	}
}

func setupIptablesRule(name string, args ...string) {
	if _, err := exec.LookPath(name); err != nil {
		Opts.Logger.Debug("command not found, skipping iptables rule setup", slog.String("cmd", name))
		return
	}

	// 检查规则是否存在
	cmd := exec.Command(name, args...)
	err := cmd.Run()
	if err == nil {
		// 规则已存在，无需添加
		return
	}

	// 规则不存在，将 -C 替换为 -A 并添加
	addArgs := make([]string, len(args))
	copy(addArgs, args)
	for i, arg := range addArgs {
		if arg == "-C" {
			addArgs[i] = "-A"
			break
		}
	}

	cmdAdd := exec.Command(name, addArgs...)
	output, err := cmdAdd.CombinedOutput()
	if err != nil {
		Opts.Logger.Warn("failed to add iptables rule", slog.String("cmd", name+" "+strings.Join(addArgs, " ")), slog.String("error", err.Error()), slog.String("output", string(output)))
	}
}

func loadAllowedSubnets() error {
	file, err := os.Open(Opts.allowedSubnetsPath)
	if err != nil {
		return err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		_, ipNet, err := net.ParseCIDR(scanner.Text())
		if err != nil {
			return err
		}
		Opts.AllowedSubnets = append(Opts.AllowedSubnets, ipNet)
		Opts.Logger.Info("allowed subnet", slog.String("subnet", ipNet.String()))
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func main() {
	flag.Parse()
	lvl := slog.LevelInfo
	if Opts.Verbose > 0 {
		lvl = slog.LevelDebug
	}
	Opts.Logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))

	if Opts.allowedSubnetsPath != "" {
		if err := loadAllowedSubnets(); err != nil {
			Opts.Logger.Error("failed to load allowed subnets file", "path", Opts.allowedSubnetsPath, "error", err)
		}
	}

	if Opts.Protocol != "tcp" && Opts.Protocol != "udp" && Opts.Protocol != "frpudp" {
		Opts.Logger.Error("--protocol has to be one of udp, tcp, frpudp", slog.String("protocol", Opts.Protocol))
		os.Exit(1)
	}

	if Opts.AutoRules && Opts.Mark == 0 {
		Opts.Mark = 123
		Opts.Logger.Info("auto-rules enabled with mark 0, defaulting mark to 123")
	}

	if Opts.Mark < 0 {
		Opts.Logger.Error("--mark has to be >= 0", slog.Int("mark", Opts.Mark))
		os.Exit(1)
	}

	if Opts.Verbose < 0 {
		Opts.Logger.Error("-v has to be >= 0", slog.Int("verbose", Opts.Verbose))
		os.Exit(1)
	}

	if Opts.Listeners < 1 {
		Opts.Logger.Error("--listeners has to be >= 1")
		os.Exit(1)
	}

	var err error
	if Opts.ListenAddr, err = netip.ParseAddrPort(Opts.ListenAddrStr); err != nil {
		Opts.Logger.Error("listen address is malformed", "error", err)
		os.Exit(1)
	}

	if Opts.TargetAddr4, err = netip.ParseAddrPort(Opts.TargetAddr4Str); err != nil {
		Opts.Logger.Error("ipv4 target address is malformed", "error", err)
		os.Exit(1)
	}
	if !Opts.TargetAddr4.Addr().Is4() {
		Opts.Logger.Error("ipv4 target address is not IPv4")
		os.Exit(1)
	}

	if Opts.TargetAddr6, err = netip.ParseAddrPort(Opts.TargetAddr6Str); err != nil {
		Opts.Logger.Error("ipv6 target address is malformed", "error", err)
		os.Exit(1)
	}
	if !Opts.TargetAddr6.Addr().Is6() {
		Opts.Logger.Error("ipv6 target address is not IPv6")
		os.Exit(1)
	}

	if Opts.udpCloseAfter < 0 {
		Opts.Logger.Error("--close-after has to be >= 0", slog.Int("close-after", Opts.udpCloseAfter))
		os.Exit(1)
	}
	Opts.UDPCloseAfter = time.Duration(Opts.udpCloseAfter) * time.Second

	listenErrors := make(chan error, Opts.Listeners)
	for i := 0; i < Opts.Listeners; i++ {
		go listen(i, listenErrors)
	}
	for i := 0; i < Opts.Listeners; i++ {
		<-listenErrors
	}
}
