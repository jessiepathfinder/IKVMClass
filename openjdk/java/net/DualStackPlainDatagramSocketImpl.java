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

import java.io.IOException;
import static ikvm.internal.JNI.*;
import static ikvm.internal.Winsock.*;
import static java.net.net_util_md.*;
import static java.net.DualStackPlainDatagramSocketImpl_c.*;

/**
 * This class defines the plain DatagramSocketImpl that is used on
 * Windows platforms greater than or equal to Windows Vista. These
 * platforms have a dual layer TCP/IP stack and can handle both IPv4
 * and IPV6 through a single file descriptor.
 * <p>
 * Note: Multicasting on a dual layer TCP/IP stack is always done with
 * TwoStacksPlainDatagramSocketImpl. This is to overcome the lack
 * of behavior defined for multicasting over a dual layer socket by the RFC.
 *
 * @author Chris Hegarty
 */

class DualStackPlainDatagramSocketImpl extends AbstractPlainDatagramSocketImpl
{

    // true if this socket is exclusively bound
    private final boolean exclusiveBind;

    /*
     * Set to true if SO_REUSEADDR is set after the socket is bound to
     * indicate SO_REUSEADDR is being emulated
     */
    private boolean reuseAddressEmulated;

    // emulates SO_REUSEADDR when exclusiveBind is true and socket is bound
    private boolean isReuseAddress;

    DualStackPlainDatagramSocketImpl(boolean exclBind) {
        exclusiveBind = exclBind;
    }

    protected void datagramSocketCreate() throws SocketException {
        if (fd == null)
            throw new SocketException("Socket closed");

        cli.System.Net.Sockets.Socket newfd = socketCreate(false /* v6Only */);

        fd.setSocket(newfd);
    }

    protected synchronized void bind0(int lport, InetAddress laddr)
        throws SocketException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        if (laddr == null)
            throw new NullPointerException("argument address");

        socketBind(nativefd, laddr, lport, exclusiveBind);
        if (lport == 0) {
            localPort = socketLocalPort(nativefd);
        } else {
            localPort = lport;
        }
    }

    protected synchronized int peek(InetAddress address) throws IOException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        if (address == null)
            throw new NullPointerException("Null address in peek()");

        // Use peekData()
        DatagramPacket peekPacket = new DatagramPacket(new byte[1], 1);
        int peekPort = peekData(peekPacket);
        address = peekPacket.getAddress();
        return peekPort;
    }

    protected synchronized int peekData(DatagramPacket p) throws IOException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        if (p == null)
            throw new NullPointerException("packet");
        if (p.getData() == null)
            throw new NullPointerException("packet buffer");

        return socketReceiveOrPeekData(nativefd, p, timeout, connected, true /*peek*/);
    }

    protected synchronized void receive0(DatagramPacket p) throws IOException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        if (p == null)
            throw new NullPointerException("packet");
        if (p.getData() == null)
            throw new NullPointerException("packet buffer");

        socketReceiveOrPeekData(nativefd, p, timeout, connected, false /*receive*/);
    }

    protected void send(DatagramPacket p) throws IOException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        if (p == null)
            throw new NullPointerException("null packet");

        if (p.getAddress() == null ||p.getData() ==null)
            throw new NullPointerException("null address || null buffer");

        socketSend(nativefd, p.getData(), p.getOffset(), p.getLength(),
                   p.getAddress(), p.getPort(), connected);
    }

    protected void connect0(InetAddress address, int port) throws SocketException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        if (address == null)
            throw new NullPointerException("address");

        socketConnect(nativefd, address, port);
    }

    protected void disconnect0(int family /*unused*/) {
        if (fd == null || !fd.valid())
            return;   // disconnect doesn't throw any exceptions

        socketDisconnect(fd.getSocket());
    }
	
	private final Object anticlosinglock = new String("");

    protected void datagramSocketClose() {
		synchronized(anticlosinglock){
			if (fd == null || !fd.valid())
				return;   // close doesn't throw any exceptions

			socketClose(fd.getSocket());
			fd.setSocket(null);
		}
    }

    @SuppressWarnings("fallthrough")
    protected void socketSetOption(int opt, Object val) throws SocketException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

        int optionValue = 0;

        switch(opt) {
            case IP_TOS :
            case SO_RCVBUF :
            case SO_SNDBUF :
                optionValue = ((Integer)val).intValue();
                break;
            case SO_REUSEADDR :
                if (exclusiveBind && localPort != 0)  {
                    // socket already bound, emulate SO_REUSEADDR
                    reuseAddressEmulated = true;
                    isReuseAddress = (Boolean)val;
                    return;
                }
                //Intentional fallthrough
            case SO_BROADCAST :
                optionValue = ((Boolean)val).booleanValue() ? 1 : 0;
                break;
            default: /* shouldn't get here */
                throw new SocketException("Option not supported");
        }

        socketSetIntOption(nativefd, opt, optionValue);
    }

    protected Object socketGetOption(int opt) throws SocketException {
        cli.System.Net.Sockets.Socket nativefd = checkAndReturnNativeFD();

         // SO_BINDADDR is not a socket option.
        if (opt == SO_BINDADDR) {
            return socketLocalAddress(nativefd);
        }
        if (opt == SO_REUSEADDR && reuseAddressEmulated)
            return isReuseAddress;

        int value = socketGetIntOption(nativefd, opt);
        Object returnValue = null;

        switch (opt) {
            case SO_REUSEADDR :
            case SO_BROADCAST :
                returnValue =  (value == 0) ? Boolean.FALSE : Boolean.TRUE;
                break;
            case IP_TOS :
            case SO_RCVBUF :
            case SO_SNDBUF :
                returnValue = new Integer(value);
                break;
            default: /* shouldn't get here */
                throw new SocketException("Option not supported");
        }

        return returnValue;
    }

    /* Multicast specific methods.
     * Multicasting on a dual layer TCP/IP stack is always done with
     * TwoStacksPlainDatagramSocketImpl. This is to overcome the lack
     * of behavior defined for multicasting over a dual layer socket by the RFC.
     */
    protected void join(InetAddress inetaddr, NetworkInterface netIf)
        throws IOException {
        throw new IOException("Method not implemented!");
    }

    protected void leave(InetAddress inetaddr, NetworkInterface netIf)
        throws IOException {
        throw new IOException("Method not implemented!");
    }

    protected void setTimeToLive(int ttl) throws IOException {
        throw new IOException("Method not implemented!");
    }

    protected int getTimeToLive() throws IOException {
        throw new IOException("Method not implemented!");
    }

    @Deprecated
    protected void setTTL(byte ttl) throws IOException {
        throw new IOException("Method not implemented!");
    }

    @Deprecated
    protected byte getTTL() throws IOException {
        throw new IOException("Method not implemented!");
    }
    /* END Multicast specific methods */

    private cli.System.Net.Sockets.Socket checkAndReturnNativeFD() throws SocketException {
        if (fd == null || !fd.valid())
            throw new SocketException("Socket closed");

        return fd.getSocket();
    }

    /* C++ to Java porting hell, made less hellish by Jessie Lesbian */
	
	static boolean purgeOutstandingICMP(cli.System.Net.Sockets.Socket fd)
	{
		boolean got_icmp = false;
		byte[] buf = new byte[1];
		fd_set tbl = new fd_set();
		timeval t = new timeval();
		SOCKETADDRESS rmtaddr = null;

		/*
		 * Peek at the queue to see if there is an ICMP port unreachable. If there
		 * is then receive it.
		 */
		FD_ZERO(tbl);
		FD_SET(fd, tbl);
		while(true) {
			if (select(tbl, null, null, t) <= 0) {
				break;
			}
			if (recvfrom(fd, buf, 1, MSG_PEEK,
							 rmtaddr) != JVM_IO_ERR) {
				break;
			}
			if (WSAGetLastError() != WSAECONNRESET) {
				/* some other error - we don't care here */
				break;
			}

			recvfrom(fd, buf, 1, 0, rmtaddr);
			got_icmp = JNI_TRUE;
		}

		return got_icmp;
	}

    private static cli.System.Net.Sockets.Socket socketCreate(boolean v6Only) throws SocketException {
        cli.System.Net.Sockets.Socket fd;
		int rv, opt=0, t=1;

		fd = socket(AF_INET6, SOCK_DGRAM, 0);
		if (fd == INVALID_SOCKET) {
			throw NET_ThrowNew(WSAGetLastError(), "Socket creation failed");
		}

		rv = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, opt);
		if (rv == SOCKET_ERROR) {
			throw NET_ThrowNew(WSAGetLastError(), "Socket creation failed");
		}

		//SetHandleInformation((HANDLE)(UINT_PTR)fd, HANDLE_FLAG_INHERIT, FALSE);
		NET_SetSockOpt(fd, SOL_SOCKET, SO_BROADCAST, t);

		/* SIO_UDP_CONNRESET fixes a "bug" introduced in Windows 2000, which
		 * returns connection reset errors on unconnected UDP sockets (as well
		 * as connected sockets). The solution is to only enable this feature
		 * when the socket is connected.
		 */
		t = 0;
		WSAIoctl(fd ,SIO_UDP_CONNRESET ,false);

		return fd;
    }

    private static void socketBind(cli.System.Net.Sockets.Socket fd, InetAddress localAddress, int localport, boolean exclBind) throws SocketException {
        SOCKETADDRESS sa = new SOCKETADDRESS();
		int rv;

		if (NET_InetAddressToSockaddr(localAddress, localport, sa, JNI_TRUE) != 0) {
			return;
		}
		rv = NET_WinBind(fd, sa, exclBind);

		if (rv == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAEACCES) {
				WSASetLastError(WSAEADDRINUSE);
			}
			throw NET_ThrowNew(WSAGetLastError(), "Cannot bind");
		}
    }

    private static void socketConnect(cli.System.Net.Sockets.Socket fd, InetAddress address, int port) throws SocketException {
        SOCKETADDRESS sa = new SOCKETADDRESS();
		int rv;
		int t = 1;

		if (NET_InetAddressToSockaddr(address, port, sa, JNI_TRUE) != 0) {
			return;
		}

		rv = ikvm.internal.Winsock.connect(fd, sa);
		if (rv == SOCKET_ERROR) {
			throw NET_ThrowNew(WSAGetLastError(), "connect");
		}

		/* see comment in socketCreate */
		WSAIoctl(fd, SIO_UDP_CONNRESET, true);
    }

    private static void socketDisconnect(cli.System.Net.Sockets.Socket fd) {
		ikvm.internal.Winsock.connect(fd, new SOCKETADDRESS());

		/* see comment in socketCreate */
		WSAIoctl(fd, SIO_UDP_CONNRESET, false);
	}

    private static void socketClose(cli.System.Net.Sockets.Socket fd) {
        NET_SocketClose(fd);
    }

    private static int socketLocalPort(cli.System.Net.Sockets.Socket fd) throws SocketException {
        SOCKETADDRESS sa = new SOCKETADDRESS();

		if (getsockname(fd, sa) == SOCKET_ERROR) {
			throw NET_ThrowNew(WSAGetLastError(), "JVM_GetSockName");
		}
		return ntohs(GET_PORT(sa));
    }

    private static Object socketLocalAddress(cli.System.Net.Sockets.Socket fd) throws SocketException {
        SOCKETADDRESS sa;
		sa = new SOCKETADDRESS();
		int[] port = { 0 };

		if (getsockname(fd, sa) == SOCKET_ERROR) {
			throw NET_ThrowNew(WSAGetLastError(), "Error getting socket name");
		}

		return NET_SockaddrToInetAddress(sa, port);
    }

    private static int socketReceiveOrPeekData(cli.System.Net.Sockets.Socket fd, DatagramPacket dpObj, int timeout, boolean connected, boolean peek) throws IOException {
		SOCKETADDRESS sa = new SOCKETADDRESS();
		int port, rv, flags=0;
		boolean retry;
		long prevTime = 0;

		int packetBufferOffset, packetBufferLen;
		byte[] packetBuffer;

		/* if we are only peeking. Called from peekData */
		if (peek) {
			flags = MSG_PEEK;
		}

		packetBuffer = dpObj.buf;
		packetBufferOffset = dpObj.offset;
		packetBufferLen = dpObj.bufLength;
		do {
			retry = false;

			if (timeout != 0) {
				if (prevTime == 0) {
					prevTime = JVM_CurrentTimeMillis();
				}
				rv = NET_Timeout(fd, timeout);
				if (rv <= 0) {
					if (rv == 0) {
						throw new SocketTimeoutException("Receive timed out");
					} else if (rv == JVM_IO_ERR) {
						throw new SocketException("Socket closed");
					} else if (rv == JVM_IO_INTR) {
						throw new java.io.InterruptedIOException("operation interrupted");
					}
					return -1;
				}
			}

			/* receive the packet */
			rv = recvfrom(fd, packetBuffer, packetBufferOffset, packetBufferLen, flags,
						sa);

			if (rv == SOCKET_ERROR && (WSAGetLastError() == WSAECONNRESET)) {
				/* An icmp port unreachable - we must receive this as Windows
				 * does not reset the state of the socket until this has been
				 * received.
				 */
				purgeOutstandingICMP(fd);

				if (connected) {
					throw new PortUnreachableException("ICMP Port Unreachable");
				} else if (timeout != 0) {
					/* Adjust timeout */
					long newTime = JVM_CurrentTimeMillis();
					timeout -= (int)(newTime - prevTime);
					if (timeout <= 0) {
						throw new SocketTimeoutException("Receive timed out");
					}
					prevTime = newTime;
				}
				retry = true;
			}
		} while (retry);

		port = ntohs (GET_PORT(sa));

		/* truncate the data if the packet's length is too small */
		if (rv > packetBufferLen) {
			rv = packetBufferLen;
		}
		if (rv < 0) {
			if (WSAGetLastError() == WSAEMSGSIZE) {
				/* it is because the buffer is too small. It's UDP, it's
				 * unreliable, it's all good. discard the rest of the
				 * data..
				 */
				rv = packetBufferLen;
			} else {
				/* failure */
				dpObj.length = 0;
			}
		}

		if (rv == -1) {
			throw new SocketException("socket closed");
		} else if (rv == -2) {
			throw new java.io.InterruptedIOException("operation interrupted");
		} else if (rv < 0) {
			throw NET_ThrowCurrent("Datagram receive failed");
		} else {
			InetAddress packetAddress;
			/*
			 * Check if there is an InetAddress already associated with this
			 * packet. If so, we check if it is the same source address. We
			 * can't update any existing InetAddress because it is immutable
			 */
			packetAddress = dpObj.address;
			if (packetAddress != NULL) {
				if (!NET_SockaddrEqualsInetAddress(sa,
												   packetAddress)) {
					/* force a new InetAddress to be created */
					packetAddress = null;
				}
			}
			if (packetAddress == NULL) {
				int[] tmp = { port };
				packetAddress = NET_SockaddrToInetAddress(sa, tmp);
				port = tmp[0];
				if (packetAddress != NULL) {
					/* stuff the new Inetaddress into the packet */
					dpObj.address = packetAddress;
				}
			}

			/* populate the packet */
			dpObj.port = port;
			dpObj.length = rv;
		}

		return port;
    }

    private static void socketSend(cli.System.Net.Sockets.Socket fd, byte[] data, int offset, int length, InetAddress address, int port, boolean connected) throws IOException {
        SOCKETADDRESS sa;
		int rv;

		if (connected) {
			sa = null; /* arg to JVM_Sendto () null in this case */
		} else {
			sa = new SOCKETADDRESS();
			if (NET_InetAddressToSockaddr(address, port, sa,
										   JNI_TRUE) != 0) {
				return;
			}
		}

		rv = sendto(fd, data, offset, length, 0, sa);
		if (rv == SOCKET_ERROR) {
			if (rv == JVM_IO_ERR) {
				throw NET_ThrowNew(WSAGetLastError(), "Datagram send failed");
			} else if (rv == JVM_IO_INTR) {
				throw new java.io.InterruptedIOException("operation interrupted");
			}
		}
    }

    private static void socketSetIntOption(cli.System.Net.Sockets.Socket fd, int cmd, int optionValue) throws SocketException {
		int[] level = { 0 }, opt = { 0 };
		if (NET_MapSocketOption(cmd, level, opt) < 0) {
			throw new SocketException("Invalid option");
		}

		if (NET_SetSockOpt(fd, level[0], opt[0], optionValue) < 0) {
			throw new SocketException("Invalid option");
		}
    }

    private static int socketGetIntOption(cli.System.Net.Sockets.Socket fd, int cmd) throws SocketException {
        int[] level = { 0 }, opt = { 0 }, result = { 0 };

		if (NET_MapSocketOption(cmd, level, opt) < 0) {
			throw new SocketException("Invalid option");
		}

		if (NET_GetSockOpt(fd, level[0], opt[0], result) < 0) {
			throw NET_ThrowNew(WSAGetLastError(), "getsockopt");
		}

		return result[0];
	}
	
	@Override int dataAvailable(){
		//A pretty bad implementation
		int peek = -1;
		synchronized(anticlosinglock){
			cli.System.Net.Sockets.Socket myfuckingstupidsocket = checkAndReturnNativeFD();
			if (myfuckingstupidsocket != null){
				try{
					peek = myfuckingstupidsocket.get_Available();
				} catch (Throwable shit){
					
				}
			}
			//FUCK that stupid peek method!
			if (peek == -1){
				if (connectedAddress == null) {
					
				} else if (isClosed()) {
					
				} else{
					try{
						peek = peek(connectedAddress);
					} catch (Throwable fuckingThrowable){
						
					}
					if(peek != -1){
						peek = 1;
					}
				}
			}
		}
		return peek;
	}
}
