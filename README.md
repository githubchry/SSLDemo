
# ssldemo

代码搬运：https://my.oschina.net/jjyuangu/blog/3007805


## 生成RSA私钥和公钥
搬运：http://zhoulifa.bokee.com/6079257.html

首先得安装OpenSSL软件包openssl，安装了这个软件包之后，我们可以做这些事情：
```
  o  Creation of RSA, DH and DSA Key Parameters # 创建密钥 key
  o  Creation of X.509 Certificates, CSRs and CRLs # 创建证书
  o  Calculation of Message Digests                # 
  o  Encryption and Decryption with Ciphers # 加密、解密
  o  SSL/TLS Client and Server Tests        # SSL 服务器端/客户端测试
  o  Handling of S/MIME signed or encrypted Mail  # 处理签名或加密了的邮件
```

### 1、生成RSA密钥的方法
`openssl genrsa -des3 -out privkey.key 2048`

这个命令会生成一个2048位的密钥，同时有一个des3方法加密的密码，如果你不想要每次都输入密码，可以改成：

`openssl genrsa -out privkey.key 2048`

建议用2048位密钥，少于此可能会不安全或很快将不安全。

### 2、生成一个证书请求
`openssl req -new -key privkey.key -out cert.csr`

这个命令将会生成一个证书请求，当然，用到了前面生成的密钥privkey.key文件
这里将生成一个新的文件cert.csr，即一个证书请求文件，你可以拿着这个文件去数字证书颁发机构（即CA）申请一个数字证书。CA会给你一个新的文件cacert.pem，那才是你的数字证书。

如果是自己做测试，那么证书的申请机构和颁发机构都是自己。就可以用下面这个命令来生成证书：

`openssl req -new -x509 -key privkey.key -out cacert.pem -days 1095`

这个命令将用上面生成的密钥privkey.key生成一个数字证书cacert.pem

### 3、使用数字证书和密钥
有了privkey.key和cacert.pem文件后就可以在自己的程序中使用了，比如做一个加密通讯的服务器

## 编译
`gcc -Wall ssl-client.c -o client -lssl -lcrypto`

`gcc -Wall ssl-server.c -o server -lssl -lcrypto`

`g++ -Wall main.cpp Socket.cpp -o server_nonblock -lssl -lcrypto`


## 运行
`./server 20190 1 127.0.0.1 cacert.pem privkey.key`

`./client 127.0.0.1 20190`

## 另外解决服务端非阻塞模式下通讯失败问题
详见socket.cc
