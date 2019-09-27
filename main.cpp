#include "Socket.h"
#include <unistd.h>

int main()
{
    char buf[2048] = { 0 };
    int len = 0;
    int ret = -1;

    Socket *src = new Socket;

    src->InitSSLCTX();
    src->Listen("0.0.0.0", 20190);

    uint32_t ip = 0;
    Socket *client = nullptr;
    do
    {
        client = src->Accept(ip);
        
    } while (client == nullptr);
    
    printf("ip %u, client->ctx  %d\n", ip, client->ctx);

    memset(buf, 0, sizeof(buf));
    strcpy(buf, "hello, diaomao.");

    /* 发消息给客户端*/
    if (client->Send(buf, strlen(buf)))
    {
        printf("消息'%s'发送成功！\n", buf);
    }
    else
    {
        printf("消息'%s'发送失败！返回值：%d\n", buf, ret);
        /* 关闭socket */
        client->Close();
    }
    
    while (1)
    {
        memset(buf, 0, sizeof(buf));
        len = client->Recv(buf, sizeof(buf));
        //len = SSL_read(client->ssl, buf, sizeof(buf));
        if (len > 0)  
            printf("接收消息成功:'%s'，共%d个字节的数据\n",  buf, len);  

        else if (len < 0)  
        {
            printf("client 断开了连接:\n");
            client->Close();
            break; 
        } 

    }
    


    return 0;
} 