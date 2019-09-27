#ifndef		__ENGINE_SOCKET_H_INCLUDED__
#define		__ENGINE_SOCKET_H_INCLUDED__

#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>
/**
 * TCP socket to remove platform dependency.
 */
struct Socket {
	int ctx;

	SSL_CTX *sslctx = nullptr;
	SSL *ssl = nullptr;

	Socket();
	virtual ~Socket();

	bool InitSSLCTX();
	bool DeinitSSLCTX();

	/**
	 * Connect to TCP server.
	 *
	 * \param ip IP address of remote server.
	 * \param port Port to connect to.
	 * \return Is connected with remote server successfully?
	 */
	bool Connect(const std::string & ip, int port);

	/**
	 * Listen on given address for connections.
	 *
	 * \param ip Bind listen ip.
	 * \param port Port to listen on.
	 * \return Is listen on given address successfully?
	 */
	bool Listen(const std::string & ip, int port);

	/**
	 * Accept connection request.
	 *
	 * \param ip IP address of request client.
	 * \return Accepted client socket. nullptr for no request coming.
	 */
	Socket * Accept(uint32_t & ip);

	/**
	 * Receive data.
	 *
	 * \param buf Buffer pointer to store received data.
	 * \param size Buffer's size in bytes.
	 * \return >0 : valid received data size. =0 : data pending, should wait. -1 : peer closed. -2 : error whild reading data.
	 */
	int Recv(char * buf, size_t size);

	/**
	 * Send data to remote server/client.
	 *
	 * \param data Buffer stores data to be sent.
	 * \param size Size of data in bytes to be sent.
	 * \return Send successfully?
	 */
	bool Send(const char * data, size_t size);

	/**
	 * Close connection.
	 */
	void Close();
};

#endif//!	__ENGINE_SOCKET_H_INCLUDED__