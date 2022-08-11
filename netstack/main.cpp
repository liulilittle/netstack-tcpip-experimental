#pragma once

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#ifdef _WIN32
#include <WinSock2.h>
#include <Windows.h>

#pragma comment(lib, "Ws2_32.lib")
#else
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/file.h>
#endif

#include <functional>
#include <mutex>
#include <utility>
#include <memory>
#include <thread>
#include <map>
#include <set>
#include <list>
#include <vector>
#include <unordered_set>
#include <unordered_map>

#include <boost/function.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <linkedlist.h>
#ifdef _WIN32
namespace boost { // boost::asio::posix::stream_descriptor
	namespace asio {
		namespace posix {
			typedef boost::asio::windows::stream_handle stream_descriptor;
		}
	}
}
#include <tap-windows.h>
#else
namespace boost {
	namespace asio {
		typedef io_service io_context;
	}
}
#endif

#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <lwip/sys.h>
#include <lwip/timeouts.h>
#include <lwip/priv/tcp_priv.h>

static boost::asio::io_context context_;
static boost::asio::posix::stream_descriptor tun_(context_);
static std::atomic<bool> init_;
static struct tcp_pcb* pcb_ = NULL;

static uint32_t MTU = 1500;
static uint32_t NETSTACK_TUN_IP = inet_addr("10.0.0.2");
#if _WIN32
static uint32_t NETSTACK_TUN_DHCP = inet_addr("10.0.0.1");
static uint32_t NETSTACK_TUN_GW = inet_addr("10.0.0.0");
#else
static uint32_t NETSTACK_TUN_GW = inet_addr("10.0.0.1");
#endif
static uint32_t NETSTACK_TUN_MASK = inet_addr("255.255.255.252");

typedef struct {
	typedef struct {
		void*										p;
		int											sz;
	} buffer_chunk;

	typedef struct {
		buffer_chunk								buf;
		std::function<void(struct tcp_pcb*)>		cb;
	} send_context;

	typedef enum {
		ENETSTACK_TCP_SENT_LWIP,
		ENETSTACK_TCP_SENT_SOCK,
		ENETSTACK_TCP_SENT_MAX
	} ENETSTACK_TCP_SENT_BUFS;

	LinkedList<send_context>						sents[ENETSTACK_TCP_SENT_MAX];
	std::shared_ptr<boost::asio::ip::tcp::socket>	socket;
	bool											open;

	struct tcp_pcb* pcb;
	ip_addr_t										local_ip;
	u16_t											local_port;
	ip_addr_t										remote_ip;
	u16_t											remote_port;
	u8_t											buf[16384];
} netstack_tcp_socket;

inline static struct pbuf*
netstack_pbuf_alloc(u16_t len) {
	if (len == 0) {
		return NULL;
	}
	return pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
}

inline static void
netstack_pbuf_free(struct pbuf* buf) {
	if (buf) {
		pbuf_free(buf);
	}
}

inline static struct tcp_pcb*
netstack_tcp_createsocket(tcp_accept_fn callback, void* arg) {
	struct tcp_pcb* pcb = tcp_new();

	tcp_bind(pcb, IP_ADDR_ANY, 0);
	pcb = tcp_listen(pcb);
	tcp_arg(pcb, arg);
	tcp_accept(pcb, callback);

	return pcb;
}

inline static std::shared_ptr<netstack_tcp_socket>
netstack_tcp_getsocket(void* p) {
	std::shared_ptr<netstack_tcp_socket>* psocket_ = (std::shared_ptr<netstack_tcp_socket>*)p;
	return psocket_ ? *psocket_ : NULL;
}

inline static std::shared_ptr<netstack_tcp_socket>
netstack_tcp_releasesocket(void* p) {
	std::shared_ptr<netstack_tcp_socket>* psocket_ = (std::shared_ptr<netstack_tcp_socket>*)p;
	if (!psocket_) {
		return NULL;
	}

	std::shared_ptr<netstack_tcp_socket> socket_ = std::move(*psocket_);
	delete psocket_;
	return std::move(socket_);
}

inline static err_t
netstack_tcp_send(struct tcp_pcb* pcb, void* data, u16_t len, const std::function<void(struct tcp_pcb*)>& callback) {
	err_t err = ERR_ARG;
	if (pcb) {
		std::shared_ptr<netstack_tcp_socket> socket_ = netstack_tcp_getsocket(pcb->callback_arg);
		if (!socket_) {
			err = ERR_ABRT;
			goto ret_;
		}

		err = ERR_OK;
		if (data && len) {
			LinkedList<netstack_tcp_socket::send_context>& sents = socket_->sents[netstack_tcp_socket::ENETSTACK_TCP_SENT_LWIP];
			if (sents.Count() > 0) {
			queue_:
				char* chunk_ = (char*)malloc(len);
				memcpy(chunk_, data, len);

				LinkedListNode<netstack_tcp_socket::send_context>* node_ = new LinkedListNode<netstack_tcp_socket::send_context>();
				netstack_tcp_socket::send_context& context_ = node_->Value;
				context_.buf = { chunk_, len };
				context_.cb = callback;

				sents.AddLast(node_);
				goto ret_;
			}

			err = tcp_write(pcb, data, len, TCP_WRITE_FLAG_COPY);
			if (err == ERR_OK) {
				if (callback) {
					callback(pcb);
				}
				goto ret_;
			}

			if (err == ERR_MEM) {
				err = ERR_OK;
				goto queue_;
			}
		}

	ret_:
		tcp_output(pcb);
	}
	return err;
}

inline static void
netstack_tcp_ack(struct tcp_pcb* pcb, int acklen) {
	if (pcb) {
		tcp_recved(pcb, acklen);
	}
}

inline static void
netstack_tcp_arg(struct tcp_pcb* pcb, void* arg) {
	if (pcb) {
		tcp_arg(pcb, arg);
	}
}

inline static void
netstack_tcp_event(struct tcp_pcb* pcb, tcp_recv_fn recv, tcp_sent_fn sent, tcp_err_fn errf, tcp_poll_fn poll) {
	if (pcb) {
		tcp_recv(pcb, recv ? recv : tcp_recv_null);
		tcp_sent(pcb, sent);
		tcp_err(pcb, errf);
		tcp_poll(pcb, poll, poll ? 1 : 0);
	}
}

inline static err_t
netstack_tcp_closesocket(struct tcp_pcb* pcb);

inline static bool
netstack_tcp_closesocket(std::shared_ptr<netstack_tcp_socket> socket_) {
	if (!socket_) {
		return false;
	}

	std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(socket_->socket);
	if (socket && socket->is_open()) {
		boost::system::error_code ec;
		try {
			socket->shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
		}
		catch (std::exception&) {}
		try {
			socket->close(ec);
		}
		catch (std::exception&) {}
	}

	for (int i = netstack_tcp_socket::ENETSTACK_TCP_SENT_LWIP; i < netstack_tcp_socket::ENETSTACK_TCP_SENT_MAX; i++) {
		LinkedList<netstack_tcp_socket::send_context>& sents = socket_->sents[i];
		while (sents.Count() > 0) {
			LinkedListNode<netstack_tcp_socket::send_context>* node = sents.First();
			netstack_tcp_socket::send_context context_ = node->Value;
			sents.RemoveFirst();
			delete node;

			free(context_.buf.p);
		}
	}

	struct tcp_pcb* pcb = socket_->pcb;
	if (pcb) {
		socket_->pcb = NULL;
	}
	netstack_tcp_closesocket(pcb);
	return true;
}

inline static err_t
netstack_tcp_closesocket(struct tcp_pcb* pcb) {
	if (!pcb) {
		return ERR_ARG;
	}

	std::shared_ptr<netstack_tcp_socket> socket_ = netstack_tcp_releasesocket(pcb->callback_arg);
	netstack_tcp_arg(pcb, NULL);
	netstack_tcp_event(pcb, NULL, NULL, NULL, NULL);

	if (socket_) {
		socket_->pcb = NULL;
		netstack_tcp_closesocket(socket_);
	}

	tcp_shutdown(pcb, 0, 1);
	return tcp_close(pcb);
}

inline static bool
netstack_server_send(std::shared_ptr<netstack_tcp_socket> socket_, void* data, int len, int flags);

inline static err_t
netstack_tcp_dorecv(void* arg, struct tcp_pcb* pcb, struct pbuf* p, err_t err) {
	int len = 0;
	if (p && err == ERR_OK) {
		std::shared_ptr<netstack_tcp_socket>* socket = (std::shared_ptr<netstack_tcp_socket>*)pcb->callback_arg;
		for (struct pbuf* q = p; p; p = p->next) {
			len += q->len;
			netstack_server_send(*socket, p->payload, p->len, TCP_WRITE_FLAG_COPY);
		}
		netstack_tcp_ack(pcb, len);
	}
	netstack_pbuf_free(p);
	if (len < 1) {
		netstack_tcp_closesocket(pcb);
	}
	return ERR_OK;
}

inline static err_t
netstack_tcp_dosent(void* arg, struct tcp_pcb* pcb, u16_t len) {
	if (pcb) {
		std::shared_ptr<netstack_tcp_socket> socket_ = netstack_tcp_getsocket(pcb->callback_arg);
		if (socket_) {
			LinkedList<netstack_tcp_socket::send_context>& sents = socket_->sents[netstack_tcp_socket::ENETSTACK_TCP_SENT_LWIP];
			while (sents.Count() > 0) { // tcp_sndbuf
				LinkedListNode<netstack_tcp_socket::send_context>* node = sents.First();
				netstack_tcp_socket::send_context context_ = node->Value;

				char* unseg_ = (char*)context_.buf.p;
				int unsent_ = context_.buf.sz;

				err_t err_ = tcp_write(pcb, unseg_, unsent_, TCP_WRITE_FLAG_COPY);
				if (err_ != ERR_OK) {
					break;
				}
				else {
					free(unseg_);

					sents.RemoveFirst();
					delete node;
				}

				if (context_.cb) {
					context_.cb(pcb);
				}
			}
		}
		tcp_output(pcb);
	}
	return ERR_OK;
}

inline static void
netstack_tcp_doerrf(void* arg, err_t err) {
	netstack_tcp_socket* p_ = (netstack_tcp_socket*)arg;
	if (p_) {
		netstack_tcp_closesocket(p_->pcb);
	}
}

inline static bool
netstack_server_connect(std::shared_ptr<netstack_tcp_socket> socket_);

inline static bool
netstack_server_dorecv(std::shared_ptr<netstack_tcp_socket> socket_);

inline static err_t
netstack_tcp_doaccept(void* arg, struct tcp_pcb* pcb, err_t err) {
	if (pcb && err == ERR_OK) {
		std::shared_ptr<netstack_tcp_socket> socket_ = std::make_shared<netstack_tcp_socket>();
		socket_->pcb = pcb;
		socket_->open = false;
		socket_->socket = std::make_shared<boost::asio::ip::tcp::socket>(context_);
		socket_->local_ip = pcb->local_ip;
		socket_->local_port = pcb->local_port;
		socket_->remote_ip = pcb->remote_ip;
		socket_->remote_port = pcb->remote_port;

		if (netstack_server_connect(socket_)) {
			netstack_tcp_arg(pcb, new std::shared_ptr<netstack_tcp_socket>(socket_));
			netstack_tcp_event(pcb, netstack_tcp_dorecv, netstack_tcp_dosent, netstack_tcp_doerrf, NULL);
		}
		else {
			netstack_tcp_closesocket(socket_);
		}
	}
	return ERR_OK;
}

inline static bool
netstack_server_send(std::shared_ptr<netstack_tcp_socket> socket_, void* data, int len, int flags) {
	if (!socket_ || !data || len < 1) {
		return false;
	}

	std::shared_ptr<boost::asio::ip::tcp::socket>& socket = socket_->socket;
	if (!socket || !socket->is_open()) {
		return false;
	}

	if (!socket_->open) {
		LinkedListNode<netstack_tcp_socket::send_context>* node_ = new LinkedListNode<netstack_tcp_socket::send_context>();
		netstack_tcp_socket::send_context& context_ = node_->Value;
		context_.buf = { memcpy(malloc(len), data, len), len };

		socket_->sents[netstack_tcp_socket::ENETSTACK_TCP_SENT_SOCK].AddLast(node_);
		return true;
	}

	std::shared_ptr<char> chunk_;
	if (flags == TCP_WRITE_FLAG_COPY) {
		data = memcpy(malloc(len), data, len);
		chunk_ = std::shared_ptr<char>((char*)data, free);
	}
	else {
		chunk_ = std::shared_ptr<char>((char*)data, [](void*) {});
	}

	boost::asio::async_write(*socket, boost::asio::buffer(data, len), [socket_, chunk_](const boost::system::error_code& ec, size_t sz) {
		if (ec) {
			netstack_tcp_closesocket(socket_);
		}
	});
	return true;
}

inline static bool
netstack_server_dorecv(std::shared_ptr<netstack_tcp_socket> socket_) {
	if (!socket_) {
		return false;
	}

	std::shared_ptr<boost::asio::ip::tcp::socket>& socket = socket_->socket;
	if (!socket || !socket->is_open()) {
		return false;
	}

	socket->async_read_some(boost::asio::buffer(socket_->buf, sizeof(socket_->buf)), [socket_](const boost::system::error_code& ec, size_t sz) {
		int by = std::max<int>(-1, ec ? -1 : sz);
		if (by < 1) {
			netstack_tcp_closesocket(socket_);
		}
		else {
			netstack_tcp_send(socket_->pcb, socket_->buf, by, [socket_](struct tcp_pcb*) {
				netstack_server_dorecv(socket_);
			});
		}
	});
	return true;
}

inline static bool
nestack_server_post_all_unsent(std::shared_ptr<netstack_tcp_socket> socket_) {
	if (!socket_) {
		return false;
	}

	LinkedList<netstack_tcp_socket::send_context>& sents = socket_->sents[netstack_tcp_socket::ENETSTACK_TCP_SENT_SOCK];
	while (sents.Count() > 0) {
		LinkedListNode<netstack_tcp_socket::send_context>* node = sents.First();
		netstack_tcp_socket::send_context context_ = node->Value;
		sents.RemoveFirst();
		delete node;

		char* chunk_ = (char*)context_.buf.p;
		int size_ = context_.buf.sz;

		netstack_server_send(socket_, chunk_, size_, 0);
	}
	return true;
}

inline static bool
netstack_server_connect(std::shared_ptr<netstack_tcp_socket> socket_) {
	if (!socket_) {
		return false;
	}

	std::shared_ptr<boost::asio::ip::tcp::socket>& socket = socket_->socket;
	if (!socket || socket->is_open()) {
		return false;
	}

	boost::system::error_code ec;
	try {
		if (IP_IS_V4_VAL(socket_->local_ip)) {
			socket->open(boost::asio::ip::tcp::v4(), ec);
		}
		else if (IP_IS_V6_VAL(socket_->local_ip)) {
			socket->open(boost::asio::ip::tcp::v6(), ec);
		}
		else {
			return false;
		}
	}
	catch (std::exception&) {
		return false;
	}

	boost::asio::ip::tcp::endpoint server(boost::asio::ip::address::from_string("185.207.153.30"), 80);
	socket->async_connect(server, [socket_](const boost::system::error_code& ec) {
		if (ec) {
			netstack_tcp_closesocket(socket_);
			return;
		}

		if (socket_->open) {
			netstack_tcp_closesocket(socket_);
			return;
		}
		else {
			socket_->open = true;
		}

		bool b = netstack_server_dorecv(socket_) && nestack_server_post_all_unsent(socket_);
		if (!b) {
			netstack_tcp_closesocket(socket_);
			return;
		}
	});
	return true;
}

inline static void
netstack_tcp_init() {
	pcb_ = netstack_tcp_createsocket(netstack_tcp_doaccept, NULL);
}

inline static std::string
netstack_ip_tostring(uint32_t address) {
	unsigned char* p = (unsigned char*)&address;
	char sz[100];
	sprintf(sz, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return sz;
}

#if _WIN32
inline static BOOL
netstack_device_io_control(
	_In_ HANDLE hDevice,
	_In_ DWORD dwIoControlCode,
	_In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
	_In_ DWORD nInBufferSize,
	_Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
	_In_ DWORD nOutBufferSize,
	_Out_opt_ LPDWORD lpBytesReturned
) {
	OVERLAPPED overlapped{ 0 };
	overlapped.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);

	BOOL status = DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, &overlapped);
	if (!status) {
		if (GetLastError() == ERROR_IO_PENDING) {
			if (WAIT_OBJECT_0 != WaitForSingleObject(overlapped.hEvent, INFINITE)) {
				assert(false);
			}
			CloseHandle(overlapped.hEvent);
			status = (overlapped.Internal == ERROR_SUCCESS);
		}
		else
			status = FALSE;
	}
	CloseHandle(overlapped.hEvent);
	return status;
}

inline static int
netstack_tun_enum(std::set<std::string>& s) {
	int components = 0;
	HKEY hOwnerKey = NULL; // {4d36e972-e325-11ce-bfc1-08002be10318}£ºÀà±ð£ºNSISÍø¿¨Çý¶¯
	char* szDevComponentId = NULL;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0,
		KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE/*KEY_ALL_ACCESS*/, &hOwnerKey) == ERROR_SUCCESS) {
		char szClassName[MAX_PATH];
		DWORD dwIndex = 0;
		while (szDevComponentId == NULL && RegEnumKeyA(hOwnerKey, dwIndex++, szClassName, MAX_PATH) == ERROR_SUCCESS) {
			BYTE data[MAX_PATH];
			DWORD dwRegType = REG_NONE;
			DWORD dwSize = sizeof(data);
			HKEY hSubKey = NULL;
			char szSubKeyPath[MAX_PATH];
			sprintf(szSubKeyPath, "%s\\%s", ADAPTER_KEY, szClassName);
			if (RegOpenKeyA(HKEY_LOCAL_MACHINE, szSubKeyPath, &hSubKey) != ERROR_SUCCESS) {
				continue;
			}
			if (RegQueryValueExA(hSubKey, "ComponentId", NULL, &dwRegType, data, &dwSize) == ERROR_SUCCESS && dwRegType == REG_SZ) {
				dwSize = sizeof(data);
				if (strncmp("tap", (char*)data, 3) == 0 && RegQueryValueExA(hSubKey, "NetCfgInstanceId", NULL,
					&dwRegType, data, &dwSize) == ERROR_SUCCESS && dwRegType == REG_SZ) {
					std::string componentid = dwSize ? std::string((char*)data, dwSize - 1) : "";
					if (s.insert(componentid).second) {
						components++;
					}
				}
			}
			RegCloseKey(hSubKey);
		}
		RegCloseKey(hOwnerKey);
	}
	return components;
}

inline static std::string
netstatck_tun_component() {
	std::set<std::string> components;
	if (netstack_tun_enum(components) < 1) {
		return "";
	}

	std::set<std::string>::iterator tail = components.begin();
	std::set<std::string>::iterator endl = components.end();
	for (; tail != endl; ++tail) {
		const std::string& component = *tail;
		if (component.empty()) {
			continue;
		}
		return component;
	}
	return "";
}

inline static uint32_t
netstack_tun_dhcp_masq(uint32_t local, uint32_t netmask, const int offset) {
	int dsa; /* DHCP server addr */

	if (offset < 0)
		dsa = (local | (~netmask)) + offset;
	else
		dsa = (local & netmask) + offset;

	if (dsa == local)
		printf("There is a clash between the --ifconfig local address and the internal DHCP server address"
			"-- both are set to %s -- please use the --ip-win32 dynamic option to choose a different free address from the"
			" --ifconfig subnet for the internal DHCP server\n", netstack_ip_tostring(dsa).data());

	if ((local & netmask) != (dsa & netmask))
		printf("--ip-win32 dynamic [offset] : offset is outside of --ifconfig subnet\n");

	return htonl(dsa);
}

inline static bool
netstack_tun_TAP_WIN_IOCTL_CONFIG_TUN(void* tun) {
	int size = 0;
	uint32_t address[3] = {
		NETSTACK_TUN_IP,
		NETSTACK_TUN_DHCP,
		NETSTACK_TUN_MASK,
	};
	memset(2 + (unsigned char*)&address[1], 0, 2); /* address[1] = htonl(dhcp_masq_addr(dhcp, address[2], 0));*/
	return netstack_device_io_control(tun, TAP_WIN_IOCTL_CONFIG_TUN, &address, sizeof(address), &address,
		sizeof(address), (LPDWORD)&size);
}

inline static bool
netstack_tun_TAP_WIN_IOCTL_CONFIG_DHCP_MASQ(void* tun) {
	int size = 0;
	uint32_t address[4] = {
		NETSTACK_TUN_IP,
		NETSTACK_TUN_MASK,
		NETSTACK_TUN_DHCP,
		365 * 24 * 3600, /* lease time in seconds */
	};
	return netstack_device_io_control(tun, TAP_WIN_IOCTL_CONFIG_DHCP_MASQ, &address, sizeof(address), &address,
		sizeof(address), (LPDWORD)&size);
}

inline static bool
netstack_tun_TAP_WIN_IOCTL_SET_MEDIA_STATUS(void* tun, bool up) {
	int size = 0;
	uint32_t address[4] = {
		NETSTACK_TUN_IP,
		NETSTACK_TUN_MASK,
		NETSTACK_TUN_DHCP,
		7 * 24 * 3600, /* lease time in seconds */
	};

	int status = up ? 1 : 0;
	return netstack_device_io_control(tun, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &status, 4, &status, 4, (LPDWORD)&size);
}
#endif

inline static void
netstack_tun_close_driver(void* tun) {
	if (tun) {
#if _WIN32
		CloseHandle((void*)tun);
#else
		close((int)tun);
#endif
	}
}

inline static void*
nestatck_tun_open_driver() {
#if _WIN32
	std::string component = netstatck_tun_component();
	if (component.empty()) {
		return NULL;
	}

	std::stringstream device;
	device << USERMODEDEVICEDIR;
	device << component.data();
	device << TAP_WIN_SUFFIX;

	void* tun = CreateFileA(
		device.str().c_str(),
		GENERIC_READ | GENERIC_WRITE,
		NULL,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_SYSTEM,
		NULL);
	return tun ? tun : (void*)(-1);
#else
	int tun = open("/dev/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (tun == -1) {
		tun = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	}
	return (void*)tun;
#endif
}

inline static void*
nestatck_tun_open() {
	void* tun = nestatck_tun_open_driver();
	if (!tun) {
		return NULL;
	}

	netstack_tun_TAP_WIN_IOCTL_CONFIG_TUN(tun);
	if (!netstack_tun_TAP_WIN_IOCTL_SET_MEDIA_STATUS(tun, true)) {
		netstack_tun_close_driver(tun);
		return NULL;
	}

	netstack_tun_TAP_WIN_IOCTL_CONFIG_DHCP_MASQ(tun);
	return tun;
}

inline static err_t
netstack_ip_output(struct pbuf* p) {
	if (!p) {
		return ERR_BUF;
	}

	if (!tun_.is_open()) {
		return ERR_IF;
	}

	if (!p->len) {
		return ERR_OK;
	}

#if _WIN32
	std::shared_ptr<char> packet = std::shared_ptr<char>((char*)malloc(p->len), free);
	pbuf_copy_partial(p, packet.get(), p->len, 0);

	tun_.async_write_some(boost::asio::buffer(packet.get(), p->len), [packet](const boost::system::error_code& ec, size_t sz) {});
	return ERR_OK;
#else
	return write(tun_.native_handle(), p->payload, p->len) > 0 ? ERR_OK : ERR_IF;
#endif
}

inline static err_t
netstack_ip_output_v4(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr) {
	LWIP_UNUSED_ARG(netif);
	LWIP_UNUSED_ARG(ipaddr);

	return netstack_ip_output(p);
}

inline static err_t
netstack_ip_output_v6(struct netif* netif, struct pbuf* p, const ip6_addr_t* ipaddr) {
	LWIP_UNUSED_ARG(netif);
	LWIP_UNUSED_ARG(ipaddr);

	return netstack_ip_output(p);
}

inline static void
netstack_ip_input(struct netif* netif, struct pbuf* packet) {
	if (netif) {
		if (packet) {
			if (packet->len) {
				netif->input(packet, netif);
			}
		}
	}
}

inline static struct netif*
netstack_init(void* tun) {
	if (tun == (void*)(-1) || init_.exchange(true)) {
		return NULL;
	}

	if (!tun) {
		tun = nestatck_tun_open();
	}

	if (tun == (void*)(-1)) {
		init_.exchange(false);
		return NULL;
	}

	boost::system::error_code ec;
#if _WIN32
	tun_.assign((void*)tun, ec);
#else
	tun_.assign((int)tun, ec);
#endif
	if (ec) {
		init_.exchange(false);
		return NULL;
	}

	sys_init();
	lwip_init();

	struct netif* netif = netif_list;
	netif->input = netif->input ? netif->input : ip_input;
	netif->output = netstack_ip_output_v4; /*netif_loop_output_ipv4*/
	netif->output_ip6 = netstack_ip_output_v6; /*netif_loop_output_ipv6*/

	ip4_addr_t ips[] = { NETSTACK_TUN_IP, NETSTACK_TUN_MASK, NETSTACK_TUN_GW };
	netif_set_ipaddr(netif, ips + 0);
	netif_set_netmask(netif, ips + 1);
	netif_set_gw(netif, ips + 2);

	netif_default = netif;
	return netif;
}

inline static bool
netstack_tun_loopback(struct netif* netif) {
	if (!netif || !tun_.is_open()) {
		return false;
	}

	struct pbuf* p_ = netstack_pbuf_alloc(MTU);
	if (!p_) {
		return false;
	}

	tun_.async_read_some(boost::asio::buffer(p_->payload, p_->len), [netif, p_](const boost::system::error_code& ec_, size_t sz) {
		if (ec_) {
			netstack_pbuf_free(p_);
		}
		else {
			netstack_ip_input(netif, p_);
		}
		netstack_tun_loopback(netif);
	});
	return true;
}

inline static int
nestack_loopback() {
	boost::asio::io_context::work work_(context_);
	boost::system::error_code ec_;
	context_.run(ec_);
	return ec_.value();
}

inline static int
nestack_processor_count() {
#if _WIN32
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return std::max<int>(1, si.dwNumberOfProcessors);
#else
	int count = 0;
#if (!defined(ANDROID) || __ANDROID_API__ >= 23)
	count = get_nprocs();
#else
	count = sysconf(_SC_NPROCESSORS_ONLN);
#endif
	if (count < 1) {
		count = 1;
	}
	return count;
#endif
}

int main() {
	struct netif* netif = netstack_init(0);
	if (!netif) {
		return -1;
	}

	netstack_tcp_init();
	netstack_tun_loopback(netif);
	return nestack_loopback();
}