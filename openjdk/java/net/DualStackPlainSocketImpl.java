/*
 * Copyright (c) 2007, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package java.net;

import java.io.*;
import static ikvm.internal.Winsock.*;
import static java.net.net_util_md.*;
import static ikvm.internal.JNI.*;
import static java.net.DualStackPlainSocketImpl_c.*;

/**
 * This class defines the plain SocketImpl that is used on Windows platforms
 * greater or equal to Windows Vista. These platforms have a dual
 * layer TCP/IP stack and can handle both IPv4 and IPV6 through a
 * single file descriptor.
 *
 * @author Chris Hegarty
 */

class DualStackPlainSocketImpl extends AbstractPlainSocketImpl
{


    // true if this socket is exclusively bound
    private final boolean exclusiveBind;

    // emulates SO_REUSEADDR when exclusiveBind is true
    private boolean isReuseAddress;

    public DualStackPlainSocketImpl(boolean exclBind) {
        exclusiveBind = exclBind;
    }

    public DualStackPlainSocketImpl(FileDescriptor fd, boolean exclBind) {
        this.fd = fd;
        exclusiveBind = exclBind;
    }

    void socketCreate(boolean stream) throws IOException {
        if (fd == null)
            throw new SocketException("Socket closed");

        cli.System.Net.Sockets.Socket newfd = socket0(stream, false /*v6 Only*/);

        fd.setSocket(newfd);
    }

    void socketConnect(InetAddress address, int port, int timeout)
        throws IOException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        if (address == null)
            throw new NullPointerException("inet address argument is null.");

        int connectResult;
        if (timeout <= 0) {
            connectResult = connect0(nativefd, address, port);
        } else {
            configureBlocking(nativefd, false);
            try {
                connectResult = connect0(nativefd, address, port);
                if (connectResult == WOULDBLOCK) {
                    waitForConnect(nativefd, timeout);
                }
            } finally {
                configureBlocking(nativefd, true);
            }
        }
        /*
         * We need to set the local port field. If bind was called
         * previous to the connect (by the client) then localport field
         * will already be set.
         */
        if (localport == 0)
            localport = localPort0(nativefd);
    }

    void socketBind(InetAddress address, int port) throws IOException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        if (address == null)
            throw new NullPointerException("inet address argument is null.");

        bind0(nativefd, address, port, exclusiveBind);
        if (port == 0) {
            localport = localPort0(nativefd);
        } else {
            localport = port;
        }

        this.address = address;
    }

    void socketListen(int backlog) throws IOException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        listen0(nativefd, backlog);
    }

    void socketAccept(SocketImpl s) throws IOException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        if (s == null)
            throw new NullPointerException("socket is null");

        cli.System.Net.Sockets.Socket newfd = null;
        InetSocketAddress[] isaa = new InetSocketAddress[1];
        if (timeout <= 0) {
            newfd = accept0(nativefd, isaa);
        } else {
            configureBlocking(nativefd, false);
            try {
                waitForNewConnection(nativefd, timeout);
                newfd = accept0(nativefd, isaa);
                if (newfd != null) {
                    configureBlocking(newfd, true);
                }
            } finally {
                configureBlocking(nativefd, true);
            }
        }
        /* Update (SocketImpl)s' fd */
        s.fd.setSocket(newfd);
        /* Update socketImpls remote port, address and localport */
        InetSocketAddress isa = isaa[0];
        s.port = isa.getPort();
        s.address = isa.getAddress();
        s.localport = localport;
    }

    int socketAvailable() throws IOException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();
        return available0(nativefd);
    }

    void socketClose0(boolean useDeferredClose/*unused*/) throws IOException {
        if (fd == null)
            throw new SocketException("Socket closed");

        if (!fd.valid())
            return;

        cli.System.Net.Sockets.Socket nativefd = fd.getSocket();
        fd.setSocket(null);
        close0(nativefd);
    }

    void socketShutdown(int howto) throws IOException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();
        shutdown0(nativefd, howto);
    }

    // Intentional fallthrough after SO_REUSEADDR
    @SuppressWarnings("fallthrough")
    void socketSetOption(int opt, boolean on, Object value)
        throws SocketException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        if (opt == SO_TIMEOUT) {  // timeout implemented through select.
            return;
        }

        int optionValue = 0;

        switch(opt) {
            case SO_REUSEADDR :
                if (exclusiveBind) {
                    // SO_REUSEADDR emulated when using exclusive bind
                    isReuseAddress = on;
                    return;
                }
                // intentional fallthrough
            case TCP_NODELAY :
            case SO_OOBINLINE :
            case SO_KEEPALIVE :
                optionValue = on ? 1 : 0;
                break;
            case SO_SNDBUF :
            case SO_RCVBUF :
            case IP_TOS :
                optionValue = ((Integer)value).intValue();
                break;
            case SO_LINGER :
                if (on) {
                    optionValue =  ((Integer)value).intValue();
                } else {
                    optionValue = -1;
                }
                break;
            default :/* shouldn't get here */
                throw new SocketException("Option not supported");
        }

        setIntOption(nativefd, opt, optionValue);
    }

    int socketGetOption(int opt, Object iaContainerObj) throws SocketException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        // SO_BINDADDR is not a socket option.
        if (opt == SO_BINDADDR) {
            localAddress(nativefd, (InetAddressContainer)iaContainerObj);
            return 0;  // return value doesn't matter.
        }

        // SO_REUSEADDR emulated when using exclusive bind
        if (opt == SO_REUSEADDR && exclusiveBind)
            return isReuseAddress? 1 : -1;

        int value = getIntOption(nativefd, opt);

        switch (opt) {
            case TCP_NODELAY :
            case SO_OOBINLINE :
            case SO_KEEPALIVE :
            case SO_REUSEADDR :
                return (value == 0) ? -1 : 1;
        }
        return value;
    }

    void socketSendUrgentData(int data) throws IOException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();
        sendOOB(nativefd, data);
    }

    private cli.System.Net.Sockets.Socket checkAndReturnNativeFD() throws SocketException {
        if (fd == null || !fd.valid())
            throw new SocketException("Socket closed");

        return fd.getSocket();
    }

    static final int WOULDBLOCK = -2;       // Nothing available (non-blocking)

    /* Native methods */

    static cli.System.Net.Sockets.Socket socket0(boolean stream, boolean v6Only) throws IOException {
        int rv, opt=0;

        cli.System.Net.Sockets.Socket fd = NET_Socket(AF_INET6, (stream ? SOCK_STREAM : SOCK_DGRAM), 0);
        if (fd == INVALID_SOCKET) {
            throw NET_ThrowNew(WSAGetLastError(), "create");
        }
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, opt) == SOCKET_ERROR) {
            throw NET_ThrowNew(WSAGetLastError(), "create");
        }
        return fd;
    }

    static void bind0(cli.System.Net.Sockets.Socket fd, InetAddress iaObj, int port,
                             boolean exclBind)
        throws IOException {
        SOCKETADDRESS sa = new SOCKETADDRESS();
        int rv;

        if (NET_InetAddressToSockaddr(iaObj, port, sa, JNI_TRUE) == 0) {
            if (NET_WinBind(fd, sa, exclBind) == SOCKET_ERROR){
                throw NET_ThrowNew(WSAGetLastError(), "JVM_Bind");
            }
        }
    }

    static int connect0(cli.System.Net.Sockets.Socket fd, InetAddress iaObj, int port)
        throws IOException {
        SOCKETADDRESS sa = new SOCKETADDRESS();

        if (NET_InetAddressToSockaddr(iaObj, port, sa,
                                     JNI_TRUE) != 0) {
          return -1;
        }

        if (connect(fd, sa) == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                return java.net.DualStackPlainSocketImpl.WOULDBLOCK;
            } else if (err == WSAEADDRNOTAVAIL) {
                throw new ConnectException("connect: Address is invalid on local machine, or port is not valid on remote machine");
            } else {
                throw NET_ThrowNew(err, "connect");
            }
        }
        return rv;
    }

    static void waitForConnect(cli.System.Net.Sockets.Socket fd, int timeout) throws IOException {
        int rv, retry;
        fd_set wr, ex;
        wr = new fd_set(); ex = new fd_set();
        timeval t = new timeval();

        FD_ZERO(wr);
        FD_ZERO(ex);
        FD_SET(fd, wr);
        FD_SET(fd, ex);
        t.tv_sec = timeout / 1000;
        t.tv_usec = (timeout % 1000) * 1000;

        /*
         * Wait for timeout, connection established or
         * connection failed.
         */
        rv = select(null, wr, ex, t);

        /*
         * Timeout before connection is established/failed so
         * we throw exception and shutdown input/output to prevent
         * socket from being used.
         * The socket should be closed immediately by the caller.
         */
        if (rv == 0) {
            shutdown( fd, SD_BOTH );
            throw new SocketTimeoutException("connect timed out");
        }

        /*
         * Socket is writable or error occurred. On some Windows editions
         * the socket will appear writable when the connect fails so we
         * check for error rather than writable.
         */
        if (FD_ISSET(fd, ex)) {
            for (retry=0; retry<3; retry++) {
                int[] tmp = { 0 };
                NET_GetSockOpt(fd, SOL_SOCKET, SO_ERROR, tmp);
                rv = tmp[0];
                if (rv != 0) {
                    break;
                }
                Sleep(0);
            }

            if (rv == 0) {
                throw new SocketException("Unable to establish connection");
            } else {
                throw NET_ThrowNew(rv, "connect");
            }
        }
    }

    static int localPort0(cli.System.Net.Sockets.Socket fd) throws IOException {
        SOCKETADDRESS sa;
        sa = new SOCKETADDRESS();

        if (getsockname(fd, sa) == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAENOTSOCK) {
                throw new SocketException("Socket closed");
            } else {
                throw NET_ThrowNew( WSAGetLastError(), "getsockname failed");
            }
        } else{
            return ntohs(GET_PORT(sa));
        }
    }

    static void localAddress(cli.System.Net.Sockets.Socket fd, InetAddressContainer iaContainerObj) throws SocketException {
        int[] port = { 0 };
        SOCKETADDRESS sa;
        sa = new SOCKETADDRESS();
        if (getsockname(fd, sa) == SOCKET_ERROR) {
            throw NET_ThrowNew(WSAGetLastError(), "Error getting socket name");
        } else{
            InetAddress iaObj = NET_SockaddrToInetAddress(env, sa, port);
            iaContainerObj.addr = iaObj;
        }
    }

    static void listen0(cli.System.Net.Sockets.Socket fd, int backlog) throws IOException {
        if (listen(fd, backlog) == SOCKET_ERROR) {
            throw NET_ThrowNew(WSAGetLastError(), "listen failed");
        }
    }

    static cli.System.Net.Sockets.Socket accept0(cli.System.Net.Sockets.Socket fd, InetSocketAddress[] isaa) throws IOException {
        cli.System.Net.Sockets.Socket newfd;
        int[] port = { 0 };
        InetSocketAddress isa;
        InetAddress ia;
        SOCKETADDRESS sa;
        sa = new SOCKETADDRESS();
        newfd = accept(fd, sa);
        if (newfd == INVALID_SOCKET) {
            if (WSAGetLastError() == -2) {
                throw new java.io.InterruptedIOException("operation interrupted");
            } else {
                throw new SocketException("socket closed");
            }
        } else{
            ia = NET_SockaddrToInetAddress(env, sa, port);
            isa = new InetSocketAddress(ia, port[0]);
            isaa[0] = isa;
            return newfd;
        }
    }

    static void waitForNewConnection(cli.System.Net.Sockets.Socket fd, int timeout) throws IOException {
        int rv = NET_Timeout(fd, timeout);
        if (rv == 0) {
            throw new SocketTimeoutException("Accept timed out");
        } else if (rv == -1) {
            throw new SocketException("socket closed");
        } else if (rv == -2) {
            throw new InterruptedIOException("operation interrupted");
        }
    }

    static int available0(cli.System.Net.Sockets.Socket fd) throws IOException {
        int[] available = { -1 };
        if ((ioctlsocket(fd, FIONREAD, available)) == SOCKET_ERROR) {
            throw NET_ThrowNew(WSAGetLastError(), "socket available");
        }
        return available[0];
    }

    static void close0(cli.System.Net.Sockets.Socket fd) throws IOException {
        NET_SocketClose(fd);
    }

    static void shutdown0(cli.System.Net.Sockets.Socket fd, int howto) throws IOException {
        shutdown(fd, howto);
    }

    static void setIntOption(cli.System.Net.Sockets.Socket fd, int cmd, int value) throws SocketException {
        int[] level = { 0 };
        int[] opt = { 0 };
        linger linger;
        Object optval;

        if (NET_MapSocketOption(cmd, level, opt) < 0) {
            throw new SocketException("Invalid option");
        } else if (opt[0] == java.net.SocketOptions.SO_LINGER) {
            linger = new linger();
            if (value >= 0) {
                linger.l_onoff = 1;
                linger.l_linger = value & 0xFFFF;
            } else {
                linger.l_onoff = 0;
                linger.l_linger = 0;
            }
            optval = linger;
        } else {
            optval = value;
        }

        if (NET_SetSockOpt(fd, level[0], opt[0], optval) < 0) {
            throw NET_ThrowNew(WSAGetLastError(), "setsockopt");
        }
    }

    static int getIntOption(cli.System.Net.Sockets.Socket fd, int cmd) throws SocketException {
        int[] level = { 0 };
        int[] opt = { 0 };
        int[] result = { 0 };
        linger linger;
        Object optval;

        if (NET_MapSocketOption(cmd, level, opt) < 0) {
            throw new SocketException("Unsupported socket option");
        } else if (opt[0] == java.net.SocketOptions.SO_LINGER) {
            linger = new linger();
            optval = linger;
        } else {
            linger = null;
            optval = result;
        }

        if (NET_GetSockOpt(fd, level[0], opt[0], optval) < 0) {
            throw NET_ThrowNew(WSAGetLastError(), "getsockopt");
        }

        if (opt[0] == java.net.SocketOptions.SO_LINGER)
            return linger.l_onoff != 0 ? linger.l_linger : -1;
        else
            return result[0];
    }

    static void sendOOB(cli.System.Net.Sockets.Socket fd, int data) throws IOException {
            int n = send(fd, new byte[] { (byte)data }, 1, MSG_OOB);
            if (n == JVM_IO_ERR) {
                throw NET_ThrowNew(WSAGetLastError(), "send");
            } else if (n == JVM_IO_INTR) {
                throw new java.io.InterruptedIOException();
            }
    }

    static void configureBlocking(cli.System.Net.Sockets.Socket fd, boolean blocking) throws IOException {
        int arg;
        int result;

        if (blocking) {
            arg = SET_BLOCKING;    // 0
        } else {
            arg = SET_NONBLOCKING;   // 1
        }

        if (ioctlsocket(fd, FIONBIO, arg) == SOCKET_ERROR) {
            throw NET_ThrowNew(WSAGetLastError(), "configureBlocking");
        }
    }
}
