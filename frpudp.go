// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

type frpudpConnection struct {
	lastActivity   *int64
	clientAddr     *net.UDPAddr
	downstreamAddr *net.UDPAddr
	upstream       *net.UDPConn
	logger         *slog.Logger
}

func frpudpCloseAfterInactivity(conn *frpudpConnection, socketClosures chan<- string) {
	for {
		lastActivity := atomic.LoadInt64(conn.lastActivity)
		<-time.After(Opts.UDPCloseAfter)
		if atomic.LoadInt64(conn.lastActivity) == lastActivity {
			break
		}
	}
	conn.upstream.Close()
	if conn.downstreamAddr != nil {
		socketClosures <- conn.downstreamAddr.String()
	} else {
		socketClosures <- ""
	}
}

func frpudpCopyFromUpstream(downstream net.PacketConn, conn *frpudpConnection) {
	rawConn, err := conn.upstream.SyscallConn()
	if err != nil {
		conn.logger.Error("failed to retrieve raw connection from upstream socket", "error", err)
		return
	}

	var syscallErr error

	err = rawConn.Read(func(fd uintptr) bool {
		buf := GetBuffer()
		defer PutBuffer(buf)

		for {
			n, _, serr := syscall.Recvfrom(int(fd), buf, syscall.MSG_DONTWAIT)
			if errors.Is(serr, syscall.EWOULDBLOCK) {
				return false
			}
			if serr != nil {
				syscallErr = serr
				return true
			}
			if n == 0 {
				return true
			}

			atomic.AddInt64(conn.lastActivity, 1)

			if _, serr := downstream.WriteTo(buf[:n], conn.downstreamAddr); serr != nil {
				syscallErr = serr
				return true
			}
		}
	})

	if err == nil {
		err = syscallErr
	}
	if err != nil {
		conn.logger.Debug("failed to read from upstream", "error", err)
	}
}

func frpudpGetSocketFromMap(downstream net.PacketConn, downstreamAddr, saddr net.Addr, logger *slog.Logger,
	connMap map[string]*frpudpConnection, socketClosures chan<- string) (*frpudpConnection, error) {
	connKey := downstreamAddr.String()
	if conn := connMap[connKey]; conn != nil {
		atomic.AddInt64(conn.lastActivity, 1)
		return conn, nil
	}

	targetAddr := Opts.TargetAddr6
	if netip.MustParseAddr(downstreamAddr.(*net.UDPAddr).IP.String()).Is4() {
		targetAddr = Opts.TargetAddr4
	}

	logger = logger.With(slog.String("downstreamAddr", downstreamAddr.String()), slog.String("targetAddr", targetAddr.String()))
	dialer := net.Dialer{LocalAddr: saddr}
	if saddr != nil {
		logger = logger.With(slog.String("clientAddr", saddr.String()))
		dialer.Control = DialUpstreamControl(saddr.(*net.UDPAddr).Port)
	}

	if Opts.Verbose > 1 {
		logger.Debug("new connection")
	}

	conn, err := dialer.Dial("udp", targetAddr.String())
	if err != nil {
		logger.Debug("failed to connect to upstream", "error", err)
		return nil, err
	}

	udpConn := &frpudpConnection{upstream: conn.(*net.UDPConn),
		logger:         logger,
		lastActivity:   new(int64),
		downstreamAddr: downstreamAddr.(*net.UDPAddr)}
	if saddr != nil {
		udpConn.clientAddr = saddr.(*net.UDPAddr)
	}

	go frpudpCopyFromUpstream(downstream, udpConn)
	go frpudpCloseAfterInactivity(udpConn, socketClosures)

	connMap[connKey] = udpConn
	return udpConn, nil
}

type frpResolvedAddr struct {
	addr       net.Addr
	lastActive time.Time
}

func FRPUDPListen(listenConfig *net.ListenConfig, logger *slog.Logger, errors chan<- error) {
	ctx := context.Background()
	ln, err := listenConfig.ListenPacket(ctx, "udp", Opts.ListenAddr.String())
	if err != nil {
		logger.Error("failed to bind listener", "error", err)
		errors <- err
		return
	}

	logger.Info("listening")

	socketClosures := make(chan string, 1024)
	connectionMap := make(map[string]*frpudpConnection)
	resolvedRemoteAddrs := make(map[string]frpResolvedAddr)
	lastCleanup := time.Now()

	buffer := GetBuffer()
	defer PutBuffer(buffer)

	for {
		n, remoteAddr, err := ln.ReadFrom(buffer)
		if err != nil {
			logger.Error("failed to read from socket", "error", err)
			continue
		}

		if !CheckOriginAllowed(remoteAddr.(*net.UDPAddr).IP) {
			logger.Debug("packet origin not in allowed subnets", slog.String("remoteAddr", remoteAddr.String()))
			continue
		}

		for {
			doneClosing := false
			select {
			case mapKey := <-socketClosures:
				delete(connectionMap, mapKey)
			default:
				doneClosing = true
			}
			if doneClosing {
				break
			}
		}

		if time.Since(lastCleanup) > 10*time.Second {
			now := time.Now()
			for k, v := range resolvedRemoteAddrs {
				if now.Sub(v.lastActive) > Opts.UDPCloseAfter*5 {
					delete(resolvedRemoteAddrs, k)
				}
			}
			lastCleanup = now
		}

		connKey := remoteAddr.String()
		conn := connectionMap[connKey]

		var saddr net.Addr
		var restBytes []byte

		if conn == nil {
			// 尝试解析 PROXY 头部
			var parsedSaddr net.Addr
			var parsedRestBytes []byte
			parsedSaddr, _, parsedRestBytes, err = PROXYReadRemoteAddr(buffer[:n], UDP)
			if err == nil {
				saddr = parsedSaddr
				restBytes = parsedRestBytes
				resolvedRemoteAddrs[connKey] = frpResolvedAddr{
					addr:       saddr,
					lastActive: time.Now(),
				}
			} else {
				// 解析失败，尝试从缓存中获取 saddr
				if cached, ok := resolvedRemoteAddrs[connKey]; ok {
					saddr = cached.addr
					cached.lastActive = time.Now()
					resolvedRemoteAddrs[connKey] = cached
					restBytes = buffer[:n]
				} else {
					logger.Debug("failed to parse PROXY header and no cached address found", "error", err, slog.String("remoteAddr", remoteAddr.String()))
					continue
				}
			}

			conn, err = frpudpGetSocketFromMap(ln, remoteAddr, saddr, logger, connectionMap, socketClosures)
			if err != nil {
				continue
			}
		} else {
			atomic.AddInt64(conn.lastActivity, 1)
			restBytes = buffer[:n]
			if cached, ok := resolvedRemoteAddrs[connKey]; ok {
				cached.lastActive = time.Now()
				resolvedRemoteAddrs[connKey] = cached
			}
		}

		_, err = conn.upstream.Write(restBytes)
		if err != nil {
			conn.logger.Error("failed to write to upstream socket", "error", err)
		}
	}
}
