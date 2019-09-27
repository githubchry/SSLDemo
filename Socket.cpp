#include "Socket.h"
#include "print.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>
#include <fcntl.h>

Socket::Socket() {
	ctx = -1;
}

Socket::~Socket() {
	Close();
}

bool Socket::InitSSLCTX()
{
	if (sslctx)
	{
		return true;
	}
	
	/* SSL 库初始化*/
    SSL_library_init();
    /* 载入所有SSL 算法*/
    OpenSSL_add_all_algorithms();
    /* 载入所有SSL 错误消息*/
    SSL_load_error_strings();
    /* 以SSL V2 和V3 标准兼容方式产生一个SSL_CTX ，即SSL Content Text */
    sslctx = SSL_CTX_new(SSLv23_server_method());
    /* 
    也可以用SSLv2_server_method() 或SSLv3_server_method() 单独表示V2 或V3标准
    */
    if (sslctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户的数字证书， 此证书用来发送给客户端。证书里包含有公钥*/
    if (SSL_CTX_use_certificate_file(sslctx, "cacert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户私钥*/
    if (SSL_CTX_use_PrivateKey_file(sslctx, "privkey.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 检查用户私钥是否正确*/
    if (!SSL_CTX_check_private_key(sslctx))
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

	return true;
}

bool Socket::DeinitSSLCTX()
{
	if (nullptr == sslctx)
	{
		return true;
	}

	 /* 释放CTX */
    SSL_CTX_free(sslctx);
	sslctx = nullptr;

	return true;
}

bool Socket::Connect(const std::string & ip, int port) {

	assert_param_return(ctx < 0, false, "Socket::Connect failed. Already connected!");

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	assert_param_return(inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) == 1, false, "Socket::Connect failed. Bad remote address : %s!", ip.c_str());

	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert_param_return(fd >= 0, false, "Socket::Connect failed due to create socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)");

	int flags = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, O_NONBLOCK | flags) < 0) {
		close(fd);
		HyErr("Socket::Connect failed due to fcntl(fd, F_SETFL, O_NONBLOCK | flags)\n");
		return false;
	}

	if (connect(fd, (sockaddr *)&addr, sizeof(sockaddr)) < 0) {

		if (errno != EINPROGRESS) {
			close(fd);
			HyErr("Socket::Connect failed with errcode : %d", errno);
			return false;
		}

		int wait_fd = epoll_create(1);
		assert_param_return(wait_fd >= 0, false, "Socket::Connect failed due to epoll_create(1) for async waiting");

		epoll_event ev;
		ev.events = EPOLLET | EPOLLOUT | EPOLLRDHUP;
		epoll_ctl(wait_fd, EPOLL_CTL_ADD, fd, &ev);

		int count = epoll_wait(wait_fd, &ev, 1, 1000);
		close(wait_fd);
		if (count < 0 || ev.events & EPOLLRDHUP) {
			close(fd);
			HyErr("Socket::Connect failed due to timeout");
			return false;
		}
	}

	ctx = (int)fd;
	return true;
}

bool Socket::Listen(const std::string & ip, int port) {

	assert_param_return(ctx < 0, false, "Socket::Listen failed. Already connected!");

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	assert_param_return(inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) == 1, false, "Socket::Listen failed. Bad listen address : %s!", ip.c_str());


	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert_param_return(fd >= 0, false, "Socket::Listen failed due to create socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)");

	int flags = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, O_NONBLOCK | flags) < 0) {
		close(fd);
		HyErr("Socket::Listen failed due to fcntl(fd, F_SETFL, O_NONBLOCK | flags)");
		return false;
	}

	int reuse = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	if (::bind(fd, (sockaddr *)&addr, sizeof(sockaddr)) < 0 || ::listen(fd, 1024) < 0) {
		close(fd);
		HyErr("Socket::Listen failed due to bind() or listen()");
		return false;
	}

	ctx = (int)fd;
	return true;
}

Socket * Socket::Accept(uint32_t & ip) {

	if (ctx < 0) return nullptr;

	sockaddr_in addr = { 0 };
	socklen_t addr_size = sizeof(addr);
	int fd = accept(ctx, (sockaddr *)&addr, &addr_size);
	if (fd < 0) return nullptr;
	int flags = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, O_NONBLOCK | flags) < 0) {
		close(fd);
		return nullptr;
	}
	Socket * socket = new Socket;
	socket->ctx = fd;
	ip = addr.sin_addr.s_addr;
	
	/* 基于ctx 产生一个新的SSL */
	socket->ssl = SSL_new(sslctx);

	/* 将连接用户的socket 加入到SSL */
	SSL_set_fd(socket->ssl, fd);

	/* 非阻塞环境下建立SSL 连接 */
	bool is_none_err = true;
	while (is_none_err)
	{
		is_none_err = false;
		if (SSL_accept(socket->ssl) != 1)
		{
			int code = -1;
			int ret = SSL_get_error(socket->ssl, code);
			if (ret == SSL_ERROR_WANT_READ)
			{
				is_none_err = true;
			}
			else
			{
				printf("SSL_accept fail\n");
				close(fd);
				break;

			}
		}
		else
		{
			printf("SSL_accept sucess! \n");
			break;
		}
	}

	return socket;
}

int Socket::Recv(char * buf, size_t size) {

	if (ctx < 0) return -1;
	
	/* 非阻塞环境下  SSL_read*/
	int ret = 0;
	int recv = 0;
	int recved = 0;
	bool is_none_err = true;
	int code = -1;
	while (is_none_err)
	{
		recv = SSL_read(ssl, buf + recved, size - recved);
		ret = SSL_get_error(ssl, code);
		//printf("recv %d! ret:%d size %d\n", recv, ret, size);
		if(ret > 0 && SSL_ERROR_SYSCALL == ret)
		{
			recved += recv;
			break;
		}
		else if (SSL_ERROR_NONE == ret)
		{
			if(recv > 0)
			{
				recved += recv;
				if(recved >= size)
				{
					break;
				}
				continue;
			}
		}
		else 
		{
			break;
		}
	}

	//printf("========== ssl read ok. recved:%d, buf:%s, ssl:%u\n", recved, buf, ssl);

	if (recved > 0) return recved;
	if (SSL_ERROR_WANT_READ == ret) return 0;
	if (recved < 0 && errno == EAGAIN) return 0;
	return recved == 0 ? -1 : -2;
}

bool Socket::Send(const char * data, size_t size) {

	if (ctx < 0) return false;

	char * ptr = (char *)data;
	int sent = 0;
	int left = (int)size;

	while (true) {
		//sent = (int)send(ctx, ptr, left, MSG_DONTWAIT);
		sent = SSL_write(ssl, ptr, left);
		if (sent < 0) {
			if (errno == EAGAIN) {
				usleep(1000);
			} else {
				return false;
			}
		} else if (sent < left) {
			left -= sent;
			ptr += sent;
		} else if (sent == left) {
			return true;
		} else {
			return left == 0;
		}
	}
}

void Socket::Close() {
	if (ctx < 0) return;
	close(ctx);
	ctx = -1;

	if(ssl)
	{
		/* 关闭SSL 连接*/
		SSL_shutdown(ssl);
		/* 释放SSL */
		SSL_free(ssl);

		ssl = nullptr;
	}
}