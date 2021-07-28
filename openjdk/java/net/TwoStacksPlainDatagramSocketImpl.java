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
import java.io.FileDescriptor;
import sun.net.ResourceManager;
import static ikvm.internal.JNI.*;
import static ikvm.internal.Winsock.*;
import static java.net.net_util_md.*;
import static java.net.InetAddress.IPv4;
import static java.net.InetAddress.IPv6;
import static java.net.TwoStacksPlainDatagramSocketImpl_c.*;

/**
 * This class defines the plain DatagramSocketImpl that is used for all
 * Windows versions lower than Vista. It adds support for IPv6 on
 * these platforms where available.
 *
 * For backward compatibility windows platforms that do not have IPv6
 * support also use this implementation, and fd1 gets set to null
 * during socket creation.
 *
 * @author Chris Hegarty
 */

class TwoStacksPlainDatagramSocketImpl extends AbstractPlainDatagramSocketImpl
{
    /* Used for IPv6 on Windows only */
    FileDescriptor fd1;

    /*
     * Needed for ipv6 on windows because we need to know
     * if the socket was bound to ::0 or 0.0.0.0, when a caller
     * asks for it. In this case, both sockets are used, but we
     * don't know whether the caller requested ::0 or 0.0.0.0
     * and need to remember it here.
     */
    private InetAddress anyLocalBoundAddr=null;

    cli.System.Net.Sockets.Socket fduse=null; /* saved between peek() and receive() calls */

    /* saved between successive calls to receive, if data is detected
     * on both sockets at same time. To ensure that one socket is not
     * starved, they rotate using this field
     */
    cli.System.Net.Sockets.Socket lastfd=null;

    // true if this socket is exclusively bound
    private final boolean exclusiveBind;

    /*
     * Set to true if SO_REUSEADDR is set after the socket is bound to
     * indicate SO_REUSEADDR is being emulated
     */
    private boolean reuseAddressEmulated;

    // emulates SO_REUSEADDR when exclusiveBind is true and socket is bound
    private boolean isReuseAddress;
	
	private cli.System.Net.Sockets.Socket getFD() {
		FileDescriptor fdObj = this.fd;

		if (fdObj == NULL) {
			return null;
		}
		return fdObj.getSocket();
	}

	private cli.System.Net.Sockets.Socket getFD1() {
		FileDescriptor fdObj = this.fd1;

		if (fdObj == NULL) {
			return null;
		}
		return fdObj.getSocket();
	}

    TwoStacksPlainDatagramSocketImpl(boolean exclBind) {
        exclusiveBind = exclBind;
    }

    protected synchronized void create() throws SocketException {
        fd1 = new FileDescriptor();
        try {
            super.create();
        } catch (SocketException e) {
            fd1 = null;
            throw e;
        }
    }

    protected synchronized void bind(int lport, InetAddress laddr)
        throws SocketException {
        super.bind(lport, laddr);
        if (laddr.isAnyLocalAddress()) {
            anyLocalBoundAddr = laddr;
        }
    }

    @Override
    protected synchronized void bind0(int lport, InetAddress laddr)
        throws SocketException
    {
        bind0(lport, laddr, exclusiveBind);

    }

    protected synchronized void receive(DatagramPacket p)
        throws IOException {
        try {
            receive0(p);
        } finally {
            fduse = null;
        }
    }

    public Object getOption(int optID) throws SocketException {
        if (isClosed()) {
            throw new SocketException("Socket Closed");
        }

        if (optID == SO_BINDADDR) {
            if ((fd != null && fd1 != null) && !connected) {
                return anyLocalBoundAddr;
            }
            int family = connectedAddress == null ? -1 : connectedAddress.holder().getFamily();
            return socketLocalAddress(family);
        } else if (optID == SO_REUSEADDR && reuseAddressEmulated) {
            return isReuseAddress;
        } else {
            return super.getOption(optID);
        }
    }

    protected void socketSetOption(int opt, Object val)
        throws SocketException
    {
        if (opt == SO_REUSEADDR && exclusiveBind && localPort != 0)  {
            // socket already bound, emulate
            reuseAddressEmulated = true;
            isReuseAddress = (Boolean)val;
        } else {
            socketNativeSetOption(opt, val);
        }

    }

    protected boolean isClosed() {
        return (fd == null && fd1 == null) ? true : false;
    }

    protected void close() {
        if (fd != null || fd1 != null) {
            datagramSocketClose();
            ResourceManager.afterUdpClose();
            fd = null;
            fd1 = null;
        }
    }

    /* C++ to Java porting hell, made less hellish by Jessie Lesbian */

    protected synchronized void bind0(int port, InetAddress addressObj, boolean exclBind) throws SocketException {
        FileDescriptor fdObj = this.fd;
		FileDescriptor fd1Obj = this.fd1;

		cli.System.Net.Sockets.Socket fd = null;
		cli.System.Net.Sockets.Socket fd1 = null;
		int family;
		boolean ipv6_supported = ipv6_available();

		SOCKETADDRESS lcladdr = new SOCKETADDRESS();

		family = getInetAddress_family(addressObj);
		if (family == IPv6 && !ipv6_supported) {
			throw new SocketException("Protocol family not supported");
		}

		if (IS_NULL(fdObj) || (ipv6_supported && IS_NULL(fd1Obj))) {
			throw new SocketException("socket closed");
		} else {
			fd = fdObj.getSocket();
			if (ipv6_supported) {
				fd1 = fd1Obj.getSocket();
			}
		}
		if (IS_NULL(addressObj)) {
			throw new NullPointerException("argument address");
		}

		if (NET_InetAddressToSockaddr(addressObj, port, lcladdr, JNI_FALSE) != 0) {
		  return;
		}

		if (ipv6_supported) {
			ipv6bind v6bind = new ipv6bind();
			v6bind.addr = lcladdr;
			v6bind.ipv4_fd = fd;
			v6bind.ipv6_fd = fd1;
			if (NET_BindV6(v6bind, exclBind) != -1) {
				/* check if the fds have changed */
				if (v6bind.ipv4_fd != fd) {
					fd = v6bind.ipv4_fd;
					if (fd == null) {
						/* socket is closed. */
						this.fd = null;
					} else {
						/* socket was re-created */
						fdObj.setSocket(fd);
					}
				}
				if (v6bind.ipv6_fd != fd1) {
					fd1 = v6bind.ipv6_fd;
					if (fd1 == null) {
						/* socket is closed. */
						this.fd1 = null;
					} else {
						/* socket was re-created */
						fd1Obj.setSocket(fd1);
					}
				}
			} else {
				/* NET_BindV6() closes both sockets upon a failure */
				this.fd = null;
				this.fd1 = null;
				throw NET_ThrowCurrent ("Cannot bind");
			}
		} else {
			if (NET_WinBind(fd, lcladdr, exclBind) == -1) {
				if (WSAGetLastError() == WSAEACCES) {
					WSASetLastError(WSAEADDRINUSE);
				}
				throw NET_ThrowCurrent("Cannot bind");
			}
		}

		if (port == 0) {
			if (fd == null) {
				/* must be an IPV6 only socket. */
				fd = fd1;
			}
			if (getsockname(fd, lcladdr) == -1) {
				throw NET_ThrowCurrent("JVM_GetSockName");
			}
			port = ntohs(GET_PORT (lcladdr));
		}
		this.localPort = port;
    }

    protected void send(DatagramPacket packet) throws IOException {
        FileDescriptor fdObj;
		cli.System.Net.Sockets.Socket fd;

		InetAddress iaObj;
		int address;
		int family;

		int packetBufferOffset, packetBufferLen, packetPort;
		byte[] packetBuffer;
		boolean connected;

		SOCKETADDRESS rmtaddr;
		rmtaddr = new SOCKETADDRESS();

		if (IS_NULL(packet)) {
			throw new NullPointerException("null packet");
		}

		iaObj = packet.address;

		packetPort = packet.port;
		packetBufferOffset = packet.offset;
		packetBuffer = packet.buf;
		connected = this.connected;

		if (IS_NULL(iaObj) || IS_NULL(packetBuffer)) {
			throw new NullPointerException("null address || null buffer");
		}

		family = getInetAddress_family(iaObj);
		if (family == IPv4) {
			fdObj = this.fd;
		} else {
			if (!ipv6_available()) {
				throw new SocketException("Protocol not allowed");
			}
			fdObj = this.fd1;
		}

		if (IS_NULL(fdObj)) {
			throw new SocketException("Socket closed");
		}
		fd = fdObj.getSocket();

		packetBufferLen = packet.length;
		/* Note: the buffer needn't be greater than 65,536 (0xFFFF)...
		 * the maximum size of an IP packet. Anything bigger is truncated anyway.
		 */
		if (packetBufferLen > MAX_PACKET_LEN) {
			packetBufferLen = MAX_PACKET_LEN;
		}

		if (connected) {
			rmtaddr = null;
		} else {
			if (NET_InetAddressToSockaddr(iaObj, packetPort, rmtaddr, JNI_FALSE) != 0) {
				return;
			}
		}

		switch (sendto(fd, packetBuffer, packetBufferOffset, packetBufferLen, 0, rmtaddr)) {
			case JVM_IO_ERR:
				throw NET_ThrowCurrent("Datagram send failed");

			case JVM_IO_INTR:
				throw new java.io.InterruptedIOException("operation interrupted");
		}
    }

    protected synchronized int peek(InetAddress addressObj) throws IOException {
        FileDescriptor fdObj = this.fd;
		int timeout = this.timeout;
		cli.System.Net.Sockets.Socket fd;

		/* The address and family fields of addressObj */
		int address, family;

		int n;
		SOCKETADDRESS remote_addr = new SOCKETADDRESS();
		byte[] buf = new byte[1];
		boolean retry;
		long prevTime = 0;

		if (IS_NULL(fdObj)) {
			throw new SocketException("Socket closed");
		} else {
			fd = fdObj.getSocket();
			if (fd == null) {
			   throw new SocketException("Socket closed");
			}
		}
		if (IS_NULL(addressObj)) {
			throw new NullPointerException("Null address in peek()");
		} else {
			address = getInetAddress_addr(addressObj);
			/* We only handle IPv4 for now. Will support IPv6 once its in the os */
			family = AF_INET;
		}

		do {
			retry = FALSE;

			/*
			 * If a timeout has been specified then we select on the socket
			 * waiting for a read event or a timeout.
			 */
			if (timeout != 0) {
				int ret;
				prevTime = JVM_CurrentTimeMillis();
				ret = NET_Timeout (fd, timeout);
				if (ret == 0) {
					throw new SocketTimeoutException("Peek timed out");
				} else if (ret == JVM_IO_ERR) {
					throw NET_ThrowCurrent("timeout in datagram socket peek");
				} else if (ret == JVM_IO_INTR) {
					throw new java.io.InterruptedIOException("operation interrupted");
				}
			}

			/* now try the peek */
			n = recvfrom(fd, buf, 1, MSG_PEEK,
							 remote_addr);

			if (n == JVM_IO_ERR) {
				if (WSAGetLastError() == WSAECONNRESET) {
					boolean connected;

					/*
					 * An icmp port unreachable - we must receive this as Windows
					 * does not reset the state of the socket until this has been
					 * received.
					 */
					purgeOutstandingICMP(fd);

					connected =  this.connected;
					if (connected) {
						throw new PortUnreachableException("ICMP Port Unreachable");
					}

					/*
					 * If a timeout was specified then we need to adjust it because
					 * we may have used up some of the timeout befor the icmp port
					 * unreachable arrived.
					 */
					if (timeout != 0) {
						long newTime = JVM_CurrentTimeMillis();
						timeout -= (newTime - prevTime);
						if (timeout <= 0) {
							throw new SocketTimeoutException("Receive timed out");
						}
						prevTime = newTime;
					}

					/* Need to retry the recv */
					retry = TRUE;
				}
			}
		} while (retry);

		if (n == JVM_IO_ERR && WSAGetLastError() != WSAEMSGSIZE) {
			throw NET_ThrowCurrent("Datagram peek failed");
		}
		if (n == JVM_IO_INTR) {
			throw new java.io.InterruptedIOException("Unexpected error JVM_IO_INTR");
		}
		addressObj.holder().address = ntohl(remote_addr.sin_addr.s_addr);
		addressObj.holder().family = IPv4;

		/* return port */
		return ntohs(remote_addr.sin_port);
    }
	
	/*
	 * check which socket was last serviced when there was data on both sockets.
	 * Only call this if sure that there is data on both sockets.
	 */
	private cli.System.Net.Sockets.Socket checkLastFD (cli.System.Net.Sockets.Socket fd, cli.System.Net.Sockets.Socket fd1) {
		cli.System.Net.Sockets.Socket nextfd, lastfd = this.lastfd;
		if (lastfd == null) {
			/* arbitrary. Choose fd */
			this.lastfd = fd;
			return fd;
		} else {
			if (lastfd == fd) {
				nextfd = fd1;
			} else {
				nextfd = fd;
			}
			this.lastfd = nextfd;
			return nextfd;
		}
	}

    protected synchronized int peekData(DatagramPacket packet) throws IOException {
        FileDescriptor fdObj = this.fd;
		FileDescriptor fd1Obj = this.fd1;
		int timeout = this.timeout;

		byte[] packetBuffer;
		int packetBufferOffset, packetBufferLen;

		cli.System.Net.Sockets.Socket fd = null, fd1 = null, fduse = null;
		int nsockets=0, errorCode;
		int port;
		byte[] data;

		boolean checkBoth = false;
		int datalen;
		int n;
		SOCKETADDRESS remote_addr;
		remote_addr = new SOCKETADDRESS();
		boolean retry;
		long prevTime = 0;

		if (!IS_NULL(fdObj)) {
			fd = fdObj.getSocket();
			if (fd == null) {
			   throw new SocketException("Socket closed");
			}
			nsockets = 1;
		}

		if (!IS_NULL(fd1Obj)) {
			fd1 = fd1Obj.getSocket();
			if (fd1 == null) {
			   throw new SocketException("Socket closed");
			}
			nsockets ++;
		}

		switch (nsockets) {
			case 0:
				throw new SocketException("Socket closed");
			case 1:
				if (!IS_NULL(fdObj)) {
				   fduse = fd;
				} else {
				   fduse = fd1;
				}
				break;
			case 2:
				checkBoth = TRUE;
				break;
		}

		if (IS_NULL(packet)) {
			throw new NullPointerException("packet");
		}

		packetBuffer = packet.buf;

		if (IS_NULL(packetBuffer)) {
			throw new NullPointerException("packet buffer");
		}

		packetBufferOffset = packet.offset;
		packetBufferLen = packet.bufLength;

		do {
			int ret;
			retry = FALSE;

			/*
			 * If a timeout has been specified then we select on the socket
			 * waiting for a read event or a timeout.
			 */
			if (checkBoth) {
				int t = timeout == 0 ? -1: timeout;
				prevTime = JVM_CurrentTimeMillis();
				cli.System.Net.Sockets.Socket[] tmp = new cli.System.Net.Sockets.Socket[] { fduse };
				ret = NET_Timeout2 (fd, fd1, t, tmp);
				fduse = tmp[0];
				/* all subsequent calls to recv() or select() will use the same fd
				 * for this call to peek() */
				if (ret <= 0) {
					if (ret == 0) {
						throw new SocketTimeoutException("Peek timed out");
					} else if (ret == JVM_IO_ERR) {
						throw NET_ThrowCurrent("timeout in datagram socket peek");
					} else if (ret == JVM_IO_INTR) {
						throw new java.io.InterruptedIOException("operation interrupted");
					}
					return -1;
				}
				if (ret == 2) {
					fduse = checkLastFD (fd, fd1);
				}
				checkBoth = FALSE;
			} else if (timeout != 0) {
				if (prevTime == 0) {
					prevTime = JVM_CurrentTimeMillis();
				}
				ret = NET_Timeout (fduse, timeout);
				if (ret <= 0) {
					if (ret == 0) {
						throw new SocketTimeoutException("Receive timed out");
					} else if (ret == JVM_IO_ERR) {
						throw new SocketException("Socket closed");
					} else if (ret == JVM_IO_INTR) {
						throw new java.io.InterruptedIOException("operation interrupted");
					}
					return -1;
				}
			}

			/* receive the packet */
			n = recvfrom(fduse, packetBuffer, packetBufferOffset, packetBufferLen, MSG_PEEK, remote_addr);
			port = ntohs (GET_PORT(remote_addr));
			if (n == JVM_IO_ERR) {
				if (WSAGetLastError() == WSAECONNRESET) {
					boolean connected;

					/*
					 * An icmp port unreachable - we must receive this as Windows
					 * does not reset the state of the socket until this has been
					 * received.
					 */
					purgeOutstandingICMP(fduse);

					connected = this.connected;
					if (connected) {
						throw new PortUnreachableException("ICMP Port Unreachable");
					}

					/*
					 * If a timeout was specified then we need to adjust it because
					 * we may have used up some of the timeout befor the icmp port
					 * unreachable arrived.
					 */
					if (timeout != 0) {
						long newTime = JVM_CurrentTimeMillis();
						timeout -= (newTime - prevTime);
						if (timeout <= 0) {
							throw new SocketTimeoutException("Receive timed out");
						}
						prevTime = newTime;
					}
					retry = TRUE;
				}
			}
		} while (retry);

		if (n < 0) {
			errorCode = WSAGetLastError();
			/* check to see if it's because the buffer was too small */
			if (errorCode == WSAEMSGSIZE) {
				/* it is because the buffer is too small. It's UDP, it's
				 * unreliable, it's all good. discard the rest of the
				 * data..
				 */
				n = packetBufferLen;
			} else {
				/* failure */
				packet.length = 0;
			}
		}
		if (n == -1) {
			throw new SocketException("Socket closed");
		} else if (n == -2) {
			throw new java.io.InterruptedIOException("operation interrupted");
		} else if (n < 0) {
			throw NET_ThrowCurrent("Datagram receive failed");
		} else {
			InetAddress packetAddress;

			/*
			 * Check if there is an InetAddress already associated with this
			 * packet. If so we check if it is the same source address. We
			 * can't update any existing InetAddress because it is immutable
			 */
			packetAddress = packet.address;
			if (packetAddress != NULL) {
				if (!NET_SockaddrEqualsInetAddress(remote_addr, packetAddress)) {
					/* force a new InetAddress to be created */
					packetAddress = null;
				}
			}
			if (packetAddress == NULL) {
				int[] tmp = { port };
				packetAddress = NET_SockaddrToInetAddress(remote_addr, tmp);
				port = tmp[0];
				/* stuff the new Inetaddress in the packet */
				packet.address = packetAddress;
			}

			/* populate the packet */
			packet.port = port;
			packet.length = n;
		}

		/* make sure receive() picks up the right fd */
		this.fduse = fduse;

		return port;
    }

    protected synchronized void receive0(DatagramPacket packet) throws IOException {
		FileDescriptor fdObj = this.fd;
		FileDescriptor fd1Obj = this.fd1;
		int timeout = this.timeout;
		byte[] packetBuffer;
		int packetBufferOffset, packetBufferLen;
		boolean ipv6_supported = ipv6_available();

		/* as a result of the changes for ipv6, peek() or peekData()
		 * must be called prior to receive() so that fduse can be set.
		 */
		cli.System.Net.Sockets.Socket fd = null;
		cli.System.Net.Sockets.Socket fd1 = null;
		cli.System.Net.Sockets.Socket fduse = null;
		int errorCode;

		int n, nsockets=0;
		SOCKETADDRESS remote_addr = new SOCKETADDRESS();
		boolean retry;
		long prevTime = 0, selectTime=0;
		boolean connected;

		if (IS_NULL(fdObj) && IS_NULL(fd1Obj)) {
			throw new SocketException("Socket closed");
		}

		if (!IS_NULL(fdObj)) {
			fd = fdObj.getSocket();
			nsockets ++;
		}
		if (!IS_NULL(fd1Obj)) {
			fd1 = fd1Obj.getSocket();
			nsockets ++;
		}

		if (nsockets == 2) { /* need to choose one of them */
			/* was fduse set in peek? */
			fduse = this.fduse;
			if (fduse == null) {
				/* not set in peek(), must select on both sockets */
				int ret, t = (timeout == 0) ? -1: timeout;
				cli.System.Net.Sockets.Socket[] tmp = new cli.System.Net.Sockets.Socket[] { fduse };
				ret = NET_Timeout2 (fd, fd1, t, tmp);
				fduse = tmp[0];
				if (ret == 2) {
					fduse = checkLastFD (fd, fd1);
				} else if (ret <= 0) {
					if (ret == 0) {
						throw new SocketTimeoutException("Receive timed out");
					} else if (ret == JVM_IO_ERR) {
						throw new SocketException("Socket closed");
					} else if (ret == JVM_IO_INTR) {
						throw new java.io.InterruptedIOException("operation interrupted");
					}
					return;
				}
			}
		} else if (!ipv6_supported) {
			fduse = fd;
		} else if (IS_NULL(fdObj)) {
			/* ipv6 supported: and this socket bound to an IPV6 only address */
			fduse = fd1;
		} else {
			/* ipv6 supported: and this socket bound to an IPV4 only address */
			fduse = fd;
		}

		if (IS_NULL(packet)) {
			throw new NullPointerException("packet");
		}

		packetBuffer = packet.buf;

		if (IS_NULL(packetBuffer)) {
			throw new NullPointerException("packet buffer");
		}

		packetBufferOffset = packet.offset;
		packetBufferLen = packet.bufLength;

		/*
		 * If this Windows edition supports ICMP port unreachable and if we
		 * are not connected then we need to know if a timeout has been specified
		 * and if so we need to pick up the current time. These are required in
		 * order to implement the semantics of timeout, viz :-
		 * timeout set to t1 but ICMP port unreachable arrives in t2 where
		 * t2 < t1. In this case we must discard the ICMP packets and then
		 * wait for the next packet up to a maximum of t1 minus t2.
		 */
		connected = this.connected;
		if (supportPortUnreachable() && !connected && timeout != 0 &&!ipv6_supported) {
			prevTime = JVM_CurrentTimeMillis();
		}

		if (timeout != 0 && nsockets == 1) {
			int ret;
			ret = NET_Timeout(fduse, timeout);
			if (ret <= 0) {
				if (ret == 0) {
					throw new SocketTimeoutException("Receive timed out");
				} else if (ret == JVM_IO_ERR) {
					throw new SocketException("Socket closed");
				} else if (ret == JVM_IO_INTR) {
					throw new java.io.InterruptedIOException("operation interrupted");
				}
				return;
			}
		}

		/*
		 * Loop only if we discarding ICMP port unreachable packets
		 */
		do {
			retry = FALSE;

			/* receive the packet */
			n = recvfrom(fduse, packetBuffer, packetBufferOffset, packetBufferLen, 0, remote_addr);

			if (n == JVM_IO_ERR) {
				if (WSAGetLastError() == WSAECONNRESET) {
					/*
					 * An icmp port unreachable has been received - consume any other
					 * outstanding packets.
					 */
					purgeOutstandingICMP(fduse);

					/*
					 * If connected throw a PortUnreachableException
					 */

					if (connected) {
						throw new PortUnreachableException("ICMP Port Unreachable");
					}

					/*
					 * If a timeout was specified then we need to adjust it because
					 * we may have used up some of the timeout before the icmp port
					 * unreachable arrived.
					 */
					if (timeout != 0) {
						int ret;
						long newTime = JVM_CurrentTimeMillis();
						timeout -= (newTime - prevTime);
						prevTime = newTime;

						if (timeout <= 0) {
							ret = 0;
						} else {
							ret = NET_Timeout(fduse, timeout);
						}

						if (ret <= 0) {
							if (ret == 0) {
								throw new SocketTimeoutException("Receive timed out");
							} else if (ret == JVM_IO_ERR) {
								throw new SocketException("Socket closed");
							} else if (ret == JVM_IO_INTR) {
								throw new java.io.InterruptedIOException("operation interrupted");
							}
						}
					}

					/*
					 * An ICMP port unreachable was received but we are
					 * not connected so ignore it.
					 */
					retry = TRUE;
				}
			}
		} while (retry);

		if (n < 0) {
			errorCode = WSAGetLastError();
			/* check to see if it's because the buffer was too small */
			if (errorCode == WSAEMSGSIZE) {
				/* it is because the buffer is too small. It's UDP, it's
				 * unreliable, it's all good. discard the rest of the
				 * data..
				 */
				n = packetBufferLen;
			} else {
				/* failure */
				packet.length = 0;
			}
		}
		if (n == -1) {
			throw new SocketException("Socket closed");
		} else if (n == -2) {
			throw new java.io.InterruptedIOException("operation interrupted");
		} else if (n < 0) {
			throw NET_ThrowCurrent("Datagram receive failed");
		} else {
			int port;
			InetAddress packetAddress;

			/*
			 * Check if there is an InetAddress already associated with this
			 * packet. If so we check if it is the same source address. We
			 * can't update any existing InetAddress because it is immutable
			 */
			packetAddress = packet.address;

			if (packetAddress != NULL) {
				if (!NET_SockaddrEqualsInetAddress(remote_addr, packetAddress)) {
					/* force a new InetAddress to be created */
					packetAddress = null;
				}
			}
			if (packetAddress == NULL) {
				int[] tmp = { 0 };
				packetAddress = NET_SockaddrToInetAddress(remote_addr, tmp);
				port = tmp[0];
				/* stuff the new Inetaddress in the packet */
				packet.address = packetAddress;
			} else {
				/* only get the new port number */
				port = NET_GetPortFromSockaddr(remote_addr);
			}
			/* populate the packet */
			packet.port = port;
			packet.length = n;
		}
    }

    protected void setTimeToLive(int ttl) throws IOException {
        FileDescriptor fdObj = this.fd;
		FileDescriptor fd1Obj = this.fd1;
		cli.System.Net.Sockets.Socket fd = null;
		cli.System.Net.Sockets.Socket fd1 = null;

		if (IS_NULL(fdObj) && IS_NULL(fd1Obj)) {
			throw new SocketException("Socket closed");
		} else {
		  if (!IS_NULL(fdObj)) {
			fd = fdObj.getSocket();
		  }
		  if (!IS_NULL(fd1Obj)) {
			fd1 = fd1Obj.getSocket();
		  }
		}

		/* setsockopt to be correct ttl */
		if (fd != null) {
		  if (NET_SetSockOpt(fd, IPPROTO_IP, IP_MULTICAST_TTL, ttl) < 0) {
			throw NET_ThrowCurrent("set IP_MULTICAST_TTL failed");
		  }
		}

		if (fd1 != null) {
		  if (NET_SetSockOpt(fd1, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, ttl) <0) {
			throw NET_ThrowCurrent("set IPV6_MULTICAST_HOPS failed");
		  }
		}
    }

    protected int getTimeToLive() throws IOException {
        FileDescriptor fdObj = this.fd;
		FileDescriptor fd1Obj = this.fd1;
		cli.System.Net.Sockets.Socket fd = null;
		cli.System.Net.Sockets.Socket fd1 = null;
		int[] ttl = new int[1];

		if (IS_NULL(fdObj) && IS_NULL(fd1Obj)) {
			throw new SocketException("Socket closed");
		} else {
			if (!IS_NULL(fdObj)) {
				fd = fdObj.getSocket();
			}
			if (!IS_NULL(fd1Obj)) {
				fd1 = fd1Obj.getSocket();
			}
		}

		/* getsockopt of ttl */
		if (fd != null) {
			if (NET_GetSockOpt(fd, IPPROTO_IP, IP_MULTICAST_TTL, ttl) < 0) {
				throw NET_ThrowCurrent("get IP_MULTICAST_TTL failed");
			}
			return ttl[0];
		}
		if (fd1 != null) {
			if (NET_GetSockOpt(fd1, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, ttl) < 0) {
				throw NET_ThrowCurrent("get IP_MULTICAST_TTL failed");
			}
			return ttl[0];
		}
		return -1;
    }

    protected void setTTL(byte ttl) throws IOException {
        setTimeToLive(ttl & 0xFF);
    }

    protected byte getTTL() throws IOException {
        FileDescriptor fdObj = this.fd;
		FileDescriptor fd1Obj = this.fd1;
		cli.System.Net.Sockets.Socket fd = null;
		cli.System.Net.Sockets.Socket fd1 = null;
		int[] ttl = new int[1];

		if (IS_NULL(fdObj) && IS_NULL(fd1Obj)) {
			throw new SocketException("Socket closed");
		} else {
			if (!IS_NULL(fdObj)) {
				fd = fdObj.getSocket();
			}
			if (!IS_NULL(fd1Obj)) {
				fd1 = fd1Obj.getSocket();
			}
		}

		/* getsockopt of ttl */
		if (fd != null) {
			if (NET_GetSockOpt(fd, IPPROTO_IP, IP_MULTICAST_TTL, ttl) < 0) {
				throw NET_ThrowCurrent("get IP_MULTICAST_TTL failed");
			}
			return (byte) ttl[0];
		}
		if (fd1 != null) {
			if (NET_GetSockOpt(fd1, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, ttl) < 0) {
				throw NET_ThrowCurrent("get IP_MULTICAST_TTL failed");
			}
			return (byte) ttl[0];
		}
		return -1;
    }
	private static NetworkInterface Java_java_net_NetworkInterface_getByIndex(JNIEnv env, int ni_class, int index)
	{
		try {
			return NetworkInterface.getByIndex(index);
		} catch (Exception x) {
			env.Throw(x);
			return null;
		}
	}

	private static NetworkInterface Java_java_net_NetworkInterface_getByInetAddress0(JNIEnv env, int ni_class, Object address)
	{
		try {
			return NetworkInterface.getByInetAddress((InetAddress)address);
		} catch (Exception x) {
			env.Throw(x);
			return null;
		}
	}

	private void mcast_join_leave(InetAddress iaObj, NetworkInterface niObj, boolean join) throws IOException
	{
		FileDescriptor fdObj = this.fd;
		FileDescriptor fd1Obj = this.fd1;
		cli.System.Net.Sockets.Socket fd = null;
		cli.System.Net.Sockets.Socket fd1 = null;

		SOCKETADDRESS name;
		name = new SOCKETADDRESS();
		ip_mreq mname = new ip_mreq();
		ipv6_mreq mname6 = new ipv6_mreq();

		in_addr in = new in_addr();
		int ifindex;

		int family;
		boolean ipv6_supported = ipv6_available();
		int cmd ;

		if (IS_NULL(fdObj) && IS_NULL(fd1Obj)) {
			throw new SocketException("Socket closed");
		}
		if (!IS_NULL(fdObj)) {
			fd = fdObj.getSocket();
		}
		if (ipv6_supported && !IS_NULL(fd1Obj)) {
			fd1 = fd1Obj.getSocket();
		}

		if (IS_NULL(iaObj)) {
			throw new NullPointerException("address");
		}

		if (NET_InetAddressToSockaddr(iaObj, 0, name, JNI_FALSE) != 0) {
			return;
		}

		/* Set the multicast group address in the ip_mreq field
		 * eventually this check should be done by the security manager
		 */
		family = name.him.sa_family;

		if (family == AF_INET) {
			int address = name.him4.sin_addr.s_addr;
			if (!net_util_md.IN_MULTICAST(ntohl(address))) {
				throw new SocketException("not in multicast");
			}
			mname.imr_multiaddr.s_addr = address;
			if (fd == null) {
				throw new SocketException("Can't join an IPv4 group on an IPv6 only socket");
			}
			if (IS_NULL(niObj)) {
				if (NET_GetSockOpt(fd, IPPROTO_IP, IP_MULTICAST_IF, in) < 0) {
					throw NET_ThrowCurrent("get IP_MULTICAST_IF failed");
				}
				mname.imr_interface.s_addr = in.s_addr;
			} else {
				if (getInet4AddrFromIf (niObj, mname.imr_interface) != 0) {
					throw NET_ThrowCurrent("no Inet4Address associated with interface");
				}
			}

			cmd = join ? IP_ADD_MEMBERSHIP: IP_DROP_MEMBERSHIP;

			/* Join the multicast group */
			if (NET_SetSockOpt(fd, IPPROTO_IP, cmd, mname) < 0) {
				if (WSAGetLastError() == WSAENOBUFS) {
					throw new SocketException("IP_ADD_MEMBERSHIP failed (out of hardware filters?)");
				} else {
					throw new SocketException("error setting options");
				}
			}
		} else /* AF_INET6 */ {
			if (ipv6_supported) {
				in6_addr address;
				address = in6_addr.FromSockAddr(name);
				if (!IN6_IS_ADDR_MULTICAST(address)) {
					throw new SocketException("not in6 multicast");
				}
				mname6.ipv6mr_multiaddr = address;
			} else {
				throw new SocketException("IPv6 not supported");
			}
			if (fd1 == null) {
				throw new SocketException("Can't join an IPv6 group on a IPv4 socket");
			}
			if (IS_NULL(niObj)) {
				int[] tmp = { 0 };
				if (NET_GetSockOpt(fd1, IPPROTO_IPV6, IPV6_MULTICAST_IF, tmp) < 0) {
					throw NET_ThrowCurrent("get IPV6_MULTICAST_IF failed");
				}
				ifindex = tmp[0];
			} else {
				ifindex = niObj.getIndex();
				if (ifindex == -1) {
					throw NET_ThrowCurrent("get ifindex failed");
				}
			}
			mname6.ipv6mr_interface = ifindex;
			cmd = join ? IPV6_ADD_MEMBERSHIP: IPV6_DROP_MEMBERSHIP;

			/* Join the multicast group */
			if (NET_SetSockOpt(fd1, IPPROTO_IPV6, cmd, mname6) < 0) {
				if (WSAGetLastError() == WSAENOBUFS) {
					throw new SocketException("IP_ADD_MEMBERSHIP failed (out of hardware filters?)");
				} else {
					throw new SocketException("error setting options");
				}
			}
		}

		return;
	}

    protected void join(InetAddress inetaddr, NetworkInterface netIf) throws IOException {
        mcast_join_leave(inetaddr, netIf, true);
    }

    protected void leave(InetAddress inetaddr, NetworkInterface netIf) throws IOException {
        mcast_join_leave(inetaddr, netIf, false);
    }

    protected void datagramSocketCreate() throws SocketException {
        FileDescriptor fdObj = this.fd;
		FileDescriptor fd1Obj = this.fd1;
		cli.System.Net.Sockets.Socket fd = null;
		cli.System.Net.Sockets.Socket fd1 = null;
		boolean ipv6_supported = ipv6_available();

		if (IS_NULL(fdObj) || (ipv6_supported && IS_NULL(fd1Obj))) {
			throw new SocketException("Socket closed");
		} else {
			fd =  socket (AF_INET, SOCK_DGRAM, 0);
		}
		if (fd == INVALID_SOCKET) {
			throw NET_ThrowCurrent("Socket creation failed");
		}
		fdObj.setSocket(fd);
		NET_SetSockOpt(fd, SOL_SOCKET, SO_BROADCAST, true);

		if (ipv6_supported) {
			/* SIO_UDP_CONNRESET fixes a bug introduced in Windows 2000, which
			 * returns connection reset errors un connected UDP sockets (as well
			 * as connected sockets. The solution is to only enable this feature
			 * when the socket is connected
			 */
			WSAIoctl(fd,SIO_UDP_CONNRESET,false);
			fd1 = socket (AF_INET6, SOCK_DGRAM, 0);
			if (fd1 == INVALID_SOCKET) {
				throw NET_ThrowCurrent("Socket creation failed");
			}
			NET_SetSockOpt(fd1, SOL_SOCKET, SO_BROADCAST, true);
			WSAIoctl(fd1,SIO_UDP_CONNRESET,false);
			fd1Obj.setSocket(fd1);
		} else {
			/* drop the second fd */
			this.fd1 = null;
		}
    }
	
	private final Object anticlosinglock = new String("");

    protected void datagramSocketClose() {
        /*
		 * REMIND: PUT A LOCK AROUND THIS CODE
		 */
		//OK! Here you go!
		synchronized(anticlosinglock){
			FileDescriptor fdObj = this.fd;
			FileDescriptor fd1Obj = this.fd1;
			boolean ipv6_supported = ipv6_available();
			cli.System.Net.Sockets.Socket fd = null, fd1 = null;

			if (IS_NULL(fdObj) && (!ipv6_supported || IS_NULL(fd1Obj))) {
				return;
			}

			if (!IS_NULL(fdObj)) {
				fd = fdObj.getSocket();
				if (fd != null) {
					fdObj.setSocket(null);
					NET_SocketClose(fd);
				}
			}

			if (ipv6_supported && fd1Obj != NULL) {
				fd1 = fd1Obj.getSocket();
				if (fd1 == null) {
					return;
				}
				fd1Obj.setSocket(null);
				NET_SocketClose(fd1);
			}
		}
    }
	static int isAdapterIpv6Enabled(int index) {
		return java.security.AccessController.doPrivileged(new java.security.PrivilegedAction<Integer>() {
			public Integer run() {
				try {
					for (java.util.Enumeration<InetAddress> e = NetworkInterface.getByIndex(index).getInetAddresses(); e.hasMoreElements(); ) {
						if (e.nextElement() instanceof Inet6Address) {
							return 1;
						}
					}
				} catch (SocketException x) {
				}
				return 0;
			}
		}).intValue();
	}
	/*
	 * check the addresses attached to the NetworkInterface object
	 * and return the first one (of the requested family Ipv4 or Ipv6)
	 * in *iaddr
	 */

	private static int getInetAddrFromIf (int family, NetworkInterface nif, InetAddress[] iaddr) throws SocketException
	{
		InetAddress[] addrArray;
		int len;
		InetAddress addr;
		int i;

		addrArray = getNetworkInterfaceAddresses(nif);
		len = addrArray.length;

		/*
		 * Check that there is at least one address bound to this
		 * interface.
		 */
		if (len < 1) {
			throw new SocketException("bad argument for IP_MULTICAST_IF2: No IP addresses bound to interface");
		}
		for (i=0; i<len; i++) {
			int fam;
			addr = addrArray[i];
			fam = getInetAddress_family(addr);
			if (fam == family) {
				iaddr[0] = addr;
				return 0;
			}
		}
		return -1;
	}

	private static int getInet4AddrFromIf (NetworkInterface nif, in_addr iaddr) throws SocketException
	{
		InetAddress[] addr = new InetAddress[1];

		int ret = getInetAddrFromIf (IPv4, nif, addr);
		if (ret == -1) {
			return -1;
		}

		iaddr.s_addr = htonl(getInetAddress_addr(addr[0]));
		return 0;
	}
	private static void setMulticastInterface(cli.System.Net.Sockets.Socket fd, cli.System.Net.Sockets.Socket fd1, int opt, Object value) throws SocketException
	{
		boolean ipv6_supported = ipv6_available();
		if (opt == java_net_SocketOptions_IP_MULTICAST_IF) {
			/*
			 * value is an InetAddress.
			 * On IPv4 system use IP_MULTICAST_IF socket option
			 * On IPv6 system get the NetworkInterface that this IP
			 * address is bound to and use the IPV6_MULTICAST_IF
			 * option instead of IP_MULTICAST_IF
			 */
			if (ipv6_supported) {
				ikvm.internal.JNI.JNIEnv env = new ikvm.internal.JNI.JNIEnv();
				value = Java_java_net_NetworkInterface_getByInetAddress0(env, ni_class, value);
				if (value == NULL) {
					Throwable fuckingThrowable = env.ExceptionOccurred();
					if (fuckingThrowable == null) {
						throw new SocketException("bad argument for IP_MULTICAST_IF: address not bound to any interface");
					} else{
						env.ThrowPendingException();
					}
				}
				opt = java_net_SocketOptions_IP_MULTICAST_IF2;
			} else {
				in_addr in = new in_addr();
				in.s_addr = htonl(getInetAddress_addr((InetAddress)value));
				if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, in) < 0) {
					NET_ThrowByNameWithLastError("java.net.SocketException", "Error setting socket option");
				}
				return;
			}
		}

		if (opt == java_net_SocketOptions_IP_MULTICAST_IF2) {
			/*
			 * value is a NetworkInterface.
			 * On IPv6 system get the index of the interface and use the
			 * IPV6_MULTICAST_IF socket option
			 * On IPv4 system extract addr[0] and use the IP_MULTICAST_IF
			 * option. For IPv6 both must be done.
			 */
			if (ipv6_supported) {
				in_addr in = new in_addr();
				int index;

				index = ((NetworkInterface)value).getIndex();

				if ( isAdapterIpv6Enabled(index) != 0 ) {
					if (setsockopt(fd1, IPPROTO_IPV6, IPV6_MULTICAST_IF, index) < 0) {
						if (WSAGetLastError() == WSAEINVAL && index > 0) {
							throw new SocketException("IPV6_MULTICAST_IF failed (interface has IPv4 address only?)");
						} else {
							NET_ThrowByNameWithLastError(JNU_JAVANETPKG+"SocketException", "Error setting socket option");
						}
						return;
					}
				}

				/* If there are any IPv4 addresses on this interface then
				 * repeat the operation on the IPv4 fd */

				if (getInet4AddrFromIf ((NetworkInterface)value, in) < 0) {
					return;
				}
				if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, in) < 0) {
					NET_ThrowByNameWithLastError(JNU_JAVANETPKG+"SocketException", "Error setting socket option");
				}
				return;
			} else {
				in_addr in = new in_addr();
				
				if (getInet4AddrFromIf ((NetworkInterface)value, in) < 0) {
					throw new SocketException("no InetAddress instances of requested type");
				}

				if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, in) < 0) {
					throw new SocketException("Error setting socket option");
				}
				return;
			}
		}
	}

    protected void socketNativeSetOption(int opt, Object value) throws SocketException {
        cli.System.Net.Sockets.Socket fd = null;
		cli.System.Net.Sockets.Socket fd1 = null;
		int[] levelv4 = new int[1];
		int[] levelv6 = new int[1];
		int[] optnamev4 = new int[1];
		int[] optnamev6 = new int[1];
		Object optval;
		boolean ipv6_supported = ipv6_available();

		fd = getFD();

		if (ipv6_supported) {
			fd1 = getFD1();
		}
		if (fd == null && fd1 == null) {
			throw new SocketException("Socket closed");
		}

		if ((opt == java_net_SocketOptions_IP_MULTICAST_IF) ||
			(opt == java_net_SocketOptions_IP_MULTICAST_IF2)) {

			setMulticastInterface(fd, fd1, opt, value);
			return;
		}

		/*
		 * Map the Java level socket option to the platform specific
		 * level(s) and option name(s).
		 */
		if (fd1 != null) {
			if (NET_MapSocketOptionV6(opt, levelv6, optnamev6) != 0) {
				throw new SocketException("Invalid option");
			}
		}
		if (fd != null) {
			if (NET_MapSocketOption(opt, levelv4, optnamev4) != 0) {
				throw new SocketException("Invalid option");
			}
		}

		switch (opt) {
			case java_net_SocketOptions_SO_SNDBUF :
			case java_net_SocketOptions_SO_RCVBUF :
			case java_net_SocketOptions_IP_TOS :
				optval = ((Integer)value).intValue();
				break;

			case java_net_SocketOptions_SO_REUSEADDR:
			case java_net_SocketOptions_SO_BROADCAST:
			case java_net_SocketOptions_IP_MULTICAST_LOOP:
				{
					boolean on = ((Boolean)value).booleanValue();
					optval = on;
					/*
					 * setLoopbackMode (true) disables IP_MULTICAST_LOOP rather
					 * than enabling it.
					 */
					if (opt == java_net_SocketOptions_IP_MULTICAST_LOOP) {
						optval = !on;
					}
				}
				break;

			default :
				throw new SocketException("Socket option not supported by PlainDatagramSocketImpl");
		}

		if (fd1 != null) {
			if (NET_SetSockOpt(fd1, levelv6[0], optnamev6[0], optval) < 0) {
				throw NET_ThrowCurrent("setsockopt IPv6");
			}
		}
		if (fd != null) {
			if (NET_SetSockOpt(fd, levelv4[0], optnamev4[0], optval) < 0) {
				throw NET_ThrowCurrent("setsockopt");
			}
		}
    }
	private static InetAddress[] getNetworkInterfaceAddresses(final NetworkInterface nif) {
		// [IKVM] this is IKVM specific, because I don't want to use reflection (or map.xml hacks) to access the "addrs" member of NetworkInterface
		// But hey, your stupid C++ to Java porting skills introduced even more reflection!
		return java.security.AccessController.doPrivileged(new java.security.PrivilegedAction<InetAddress[]>() {
			public InetAddress[] run() {
				java.util.ArrayList<InetAddress> list = new java.util.ArrayList<InetAddress>();
				for (java.util.Enumeration<InetAddress> e = nif.getInetAddresses(); e.hasMoreElements(); ) {
					list.add(e.nextElement());
				}
				return list.toArray(new InetAddress[list.size()]);
			}
		});
	}
	private static Object getMulticastInterface(cli.System.Net.Sockets.Socket fd, cli.System.Net.Sockets.Socket fd1, int opt) throws SocketException {
		boolean isIPV4 = !ipv6_available() || fd1 == null;

		/*
		 * IPv4 implementation
		 */
		if (isIPV4) {
			Inet4Address addr = new Inet4Address();

			in_addr in = new in_addr();

			if (getsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, in) < 0) {
				NET_ThrowByNameWithLastError(JNU_JAVANETPKG+"SocketException", "Error getting socket option");
				return NULL;
			}

			/*
			 * Construct and populate an Inet4Address
			 */
			addr.holder().address = ntohl(in.s_addr);

			/*
			 * For IP_MULTICAST_IF return InetAddress
			 */
			if (opt == java_net_SocketOptions_IP_MULTICAST_IF) {
				return addr;
			}

			NetworkInterface ni = Java_java_net_NetworkInterface_getByInetAddress0(new ikvm.internal.JNI.JNIEnv(), ni_class, addr);
			if (ni != null) {
				return ni;
			}

			/*
			 * The address doesn't appear to be bound at any known
			 * NetworkInterface. Therefore we construct a NetworkInterface
			 * with this address.
			 */
			return new NetworkInterface(null, -1, new InetAddress[] { addr });
		}


		/*
		 * IPv6 implementation
		 */
		if ((opt == java_net_SocketOptions_IP_MULTICAST_IF) || (opt == java_net_SocketOptions_IP_MULTICAST_IF2)) {

			int index;

			InetAddress[] addrArray;
			InetAddress addr;
			NetworkInterface ni;

			{
				int[] tmp = { 0 };
				if (getsockopt(fd1, IPPROTO_IPV6, IPV6_MULTICAST_IF, tmp) < 0) {
					NET_ThrowByNameWithLastError( JNU_JAVANETPKG+"SocketException", "Error getting socket option");
					return NULL;
				}
				index = tmp[0];
			}

			/*
			 * If multicast to a specific interface then return the
			 * interface (for IF2) or the any address on that interface
			 * (for IF).
			 */
			if (index > 0) {
				ni = Java_java_net_NetworkInterface_getByIndex(new ikvm.internal.JNI.JNIEnv(), ni_class, index);
				if (ni == NULL) {
					throw new SocketException("IPV6_MULTICAST_IF returned index to unrecognized interface: " + index);
				}

				/*
				 * For IP_MULTICAST_IF2 return the NetworkInterface
				 */
				if (opt == java_net_SocketOptions_IP_MULTICAST_IF2) {
					return ni;
				}

				/*
				 * For IP_MULTICAST_IF return addrs[0]
				 */
				addrArray = getNetworkInterfaceAddresses(ni);
				if (addrArray.length < 1) {
					throw new SocketException("IPV6_MULTICAST_IF returned interface without IP bindings");
				}

				addr = addrArray[0];
				return addr;
			}

			/*
			 * Multicast to any address - return anyLocalAddress
			 * or a NetworkInterface with addrs[0] set to anyLocalAddress
			 */

			addr = InetAddress.anyLocalAddress();
			if (opt == java_net_SocketOptions_IP_MULTICAST_IF) {
				return addr;
			}

			return new NetworkInterface(null, -1, new InetAddress[] { addr });
		}
		return NULL;
	}
    protected Object socketGetOption(int opt) throws SocketException {
        cli.System.Net.Sockets.Socket fd = null;
		cli.System.Net.Sockets.Socket fd1 = null;
		int[] level = new int[1];
		int[] optname = new int[1];
		int[] optval = new int[1];
		boolean ipv6_supported = ipv6_available();

		fd = getFD();
		if (ipv6_supported) {
			fd1 = getFD1();
		}

		if (fd == null && fd1 ==  null) {
			throw new SocketException("Socket closed");
		}

		/*
		 * Handle IP_MULTICAST_IF separately
		 */
		if (opt == java_net_SocketOptions_IP_MULTICAST_IF ||
			opt == java_net_SocketOptions_IP_MULTICAST_IF2) {
			return getMulticastInterface(fd, fd1, opt);
		}

		/*
		 * Map the Java level socket option to the platform specific
		 * level and option name.
		 */
		if (NET_MapSocketOption(opt, level, optname) != 0) {
			throw new SocketException("Invalid option");
		}

		if (fd == null) {
			if (NET_MapSocketOptionV6(opt, level, optname) != 0) {
				throw new SocketException("Invalid option");
			}
			fd = fd1; /* must be IPv6 only */
		}

		if (NET_GetSockOpt(fd, level[0], optname[0], optval) < 0) {
			throw new SocketException("error getting socket option: " + WSAGetLastError());
		}

		switch (opt) {
			case java_net_SocketOptions_SO_BROADCAST:
			case java_net_SocketOptions_SO_REUSEADDR:
				return optval[0] != 0;

			case java_net_SocketOptions_IP_MULTICAST_LOOP:
				/* getLoopbackMode() returns true if IP_MULTICAST_LOOP is disabled */
				return optval[0] == 0;

			case java_net_SocketOptions_SO_SNDBUF:
			case java_net_SocketOptions_SO_RCVBUF:
			case java_net_SocketOptions_IP_TOS:
				return optval[0];

			default :
				throw new SocketException("Socket option not supported by TwoStacksPlainDatagramSocketImpl");
		}
    }

    protected void connect0(InetAddress address, int port) throws SocketException {
        /* The object's field */
		FileDescriptor fdObj = this.fd;
		FileDescriptor fd1Obj = this.fd1;
		/* The fdObj'fd */
		cli.System.Net.Sockets.Socket fd = null;
		cli.System.Net.Sockets.Socket fd1 = null;
		cli.System.Net.Sockets.Socket fdc;
		/* The packetAddress address, family and port */
		int addr, family;
		SOCKETADDRESS rmtaddr;
		rmtaddr = new SOCKETADDRESS();
		boolean ipv6_supported = ipv6_available();

		if (IS_NULL(fdObj) && IS_NULL(fd1Obj)) {
			throw new SocketException("Socket closed");
		}
		if (!IS_NULL(fdObj)) {
			fd = fdObj.getSocket();
		}
		if (!IS_NULL(fd1Obj)) {
			fd1 = fd1Obj.getSocket();
		}

		if (IS_NULL(address)) {
			throw new NullPointerException("address");
		}

		addr = getInetAddress_addr(address);

		family = getInetAddress_family(address);
		if (family == IPv6 && !ipv6_supported) {
			throw new SocketException("Protocol family not supported");
		}

		fdc = family == IPv4? fd: fd1;

		if (xp_or_later) {
			/* SIO_UDP_CONNRESET fixes a bug introduced in Windows 2000, which
			 * returns connection reset errors on connected UDP sockets (as well
			 * as connected sockets). The solution is to only enable this feature
			 * when the socket is connected
			 */
			WSAIoctl(fdc, SIO_UDP_CONNRESET, true);
		}

		if (NET_InetAddressToSockaddr(address, port, rmtaddr, JNI_FALSE) != 0) {
		  return;
		}

		if (ikvm.internal.Winsock.connect(fdc, rmtaddr) == -1) {
			throw NET_ThrowCurrent("connect");
		}
    }

    protected Object socketLocalAddress(int family) throws SocketException {
        cli.System.Net.Sockets.Socket fd = null;
		cli.System.Net.Sockets.Socket fd1 = null;
		SOCKETADDRESS him;
		him = new SOCKETADDRESS();
		Object iaObj;
		boolean ipv6_supported = ipv6_available();

		fd = getFD();
		if (ipv6_supported) {
			fd1 = getFD1();
		}

		if (fd == null && fd1 == null) {
			throw new SocketException("Socket closed");
		}

		/* find out local IP address */

		/* family==-1 when socket is not connected */
		if ((family == IPv6) || (family == -1 && fd == null)) {
			fd = fd1; /* must be IPv6 only */
		}

		if (fd == null) {
			throw new SocketException("Socket closed");
		}

		if (getsockname(fd, him) == -1) {
			throw new SocketException("Error getting socket name");
		}
		iaObj = NET_SockaddrToInetAddress(him, new int[1]);

		return iaObj;
    }

    protected void disconnect0(int family) {
        /* The object's field */
		FileDescriptor fdObj;
		/* The fdObj'fd */
		cli.System.Net.Sockets.Socket fd;
		SOCKETADDRESS addr = new SOCKETADDRESS();

		if (family == IPv4) {
			fdObj = this.fd;
		} else {
			fdObj = this.fd1;
		}

		if (IS_NULL(fdObj)) {
			/* disconnect doesn't throw any exceptions */
			return;
		}
		fd = fdObj.getSocket();

		ikvm.internal.Winsock.connect(fd, addr);

		/*
		 * use SIO_UDP_CONNRESET
		 * to disable ICMP port unreachable handling here.
		 */
		if (xp_or_later) {
			WSAIoctl(fd,SIO_UDP_CONNRESET,false);
		}
    }
	
	//Hopefully
	@Override int dataAvailable() throws SocketException{
		cli.System.Net.Sockets.Socket fd = getFD();
		cli.System.Net.Sockets.Socket fd1 = getFD1();
		int rv = -1;
		int rv1 = -1;
		int[] retptr = new int[1];
		retptr[0] = 0;
		if (fd != null) {	
			rv = ioctlsocket(fd, FIONREAD, retptr);
			int retval = retptr[0];
			if (retval > 0) {
				return retval;
			}
		}
		retptr[0] = 0;
		if (fd1 != null) {	
			rv1 = ioctlsocket(fd1, FIONREAD, retptr);
			int retval = retptr[0];
			if (retval > 0) {
				return retval;
			}
		}
		
	}
}
