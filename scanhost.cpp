#include "scanhost.h"
// g++ -g scanhost.cpp -o scanhost.exe -lws2_32
// scanhost 39.156.66.6 39.156.66.15
// baidu.com 39.156.66.10

// 解析相应报文
BOOL DecodeIcmpResponse(char* _Buf, int _RecvLen, DECODE_RESULT& DecodeResult) {
    // 检查数据报大小的合法性。头部是否是IP+ICMP
    IP_HEADER* _IpHdr = (IP_HEADER*)_Buf;
    int _IpHdrLen = _IpHdr->hdr_len * 4;  // 头部长度
    if (_RecvLen < (int)(_IpHdrLen + sizeof(ICMP_HEADER)))
        return FALSE;

    ICMP_HEADER* _IcmpHdr = (ICMP_HEADER*)(_Buf + _IpHdrLen);

    // ICMP回显应答报文
    if (_IcmpHdr->type == ICMP_ECHO_REPLY) {
        // 检查PID和序列号以确定是本次ICMP的回应
        if (_IcmpHdr->id != (USHORT)GetCurrentProcessId() || _IcmpHdr->seq != DecodeResult.SeqNo) {
            return false;
        }
        // 计算往返时间
        DecodeResult.RoundTripTime = std::clock() - DecodeResult.RoundTripTime;
        DecodeResult.TotalTime += DecodeResult.RoundTripTime;
        return true;
    }

    return false;
}

// 尝试连接
void try_connect(u_long ip2find) {
    sockaddr_in destSockAddr;
    memset(&(destSockAddr), 0, sizeof(destSockAddr));  // 初始化清空
    destSockAddr.sin_family = AF_INET;                 // IPV4协议族
    destSockAddr.sin_addr.s_addr = ip2find;            // 设置查找的ip地址

    // 创建原始套接字。IPPROTO_ICMP表示ICMP报头由程序构造
    // WSA_FLAG_OVERLAPPED 重叠IO。在一个I/O操作完成之前，可以发出多个相同的I/O操作，发送和接收都可以重叠
    SOCKET sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
    int iTimeout = 1000;                                                               // 超时时间(ms)
    setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&iTimeout, sizeof(iTimeout));  // 设置接收超时时间
    setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&iTimeout, sizeof(iTimeout));  // 设置发送超时时间

    // 初始化缓冲区
    char send_buf[sizeof(ICMP_HEADER) + ICMP_DATA_SIZE];  // 发送缓冲区
    memset(send_buf, 0, sizeof(send_buf));                // 初始化发送缓冲区
    char recv_buf[MAX_ICMP_PACKET_SIZE];                  // 接收缓冲区
    memset(recv_buf, 0, sizeof(recv_buf));                // 初始化接收缓冲区

    // 填充ICMP报文
    ICMP_HEADER* _IcmpHeader = (ICMP_HEADER*)send_buf;
    _IcmpHeader->type = ICMP_ECHO_REQUEST;                        // 类型为请求回显
    _IcmpHeader->code = 0;                                        // 代码字段为0
    _IcmpHeader->id = (USHORT)GetCurrentProcessId();              // ID字段为当前进程号
    memset(send_buf + sizeof(ICMP_HEADER), 'K', ICMP_DATA_SIZE);  // 后面的数据字段

    USHORT SeqNo = 0;                    // ICMP报文序列号
    int cnt = 0;                         // 记录成功数量
    int _MAX_TRY_TIMES = MAX_TRY_TIMES;  // 循环的最大次数
    DECODE_RESULT DecodeResult;          // 传递给报文解码函数的结构化参数
    DecodeResult.TotalTime = 0;

    // 开始尝试
    while (_MAX_TRY_TIMES--) {
        // 填充ICMP报文
        ((ICMP_HEADER*)send_buf)->cksum = 0;                                                                  // 效验和先置为0
        ((ICMP_HEADER*)send_buf)->seq = SeqNo++;                                                              // 填充序列号
        ((ICMP_HEADER*)send_buf)->cksum = checksum((USHORT*)send_buf, sizeof(ICMP_HEADER) + ICMP_DATA_SIZE);  // 计算效验和

        // 记录序列号和当前时间
        DecodeResult.SeqNo = ((ICMP_HEADER*)send_buf)->seq;  // 当前序号
        DecodeResult.RoundTripTime = clock();                // 当前时间

        // 发送TCP回显请求信息
        sendto(sockRaw, send_buf, sizeof(send_buf), 0, (sockaddr*)&destSockAddr, sizeof(destSockAddr));

        // 初始化接受ICMP报文的sockaddr
        sockaddr_in from;             // 对端socket地址
        int _FromLen = sizeof(from);  // 地址结构大小
        int RecvLen;                  // 接收数据长度
        while (1) {                   // 可能接收到别的数据报，故需要无限循环
            RecvLen = recvfrom(sockRaw, recv_buf, MAX_ICMP_PACKET_SIZE, 0, (sockaddr*)&from, &_FromLen);
            if (RecvLen != SOCKET_ERROR) {                                       // 有数据达到
                if (DecodeIcmpResponse(recv_buf, RecvLen, DecodeResult)) {       // 解析相应报文
                    if (from.sin_addr.s_addr == destSockAddr.sin_addr.s_addr) {  // 目标IP与相应IP一致。
                        cnt++;
                        break;
                    }
                }
            } else if (WSAGetLastError() == WSAETIMEDOUT) {  // 接收超时
                break;
            }
        }
    }

    if (cnt) {
        printf("成功！请求的主机处于活跃状态！\t\n");
        printf("数据包：已发送=%d，已接收=%d，丢失=%d, ", MAX_TRY_TIMES, cnt, MAX_TRY_TIMES - cnt);
        if (DecodeResult.TotalTime / cnt) {
            printf("平均往返时间=%dms\n", DecodeResult.TotalTime / cnt);
        } else {
            printf("平均往返时间<1ms\n");
        }
    } else {
        printf("请求IP失败。主机非活跃！\n");
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("参数数量或格式有误！请注意输入格式为：\nscanhost Start_IP End_IP\n");
        exit(1);
    }
    // 点分十进制的IP转换失败
    if (inet_addr(argv[1]) == INADDR_NONE) {
        printf("输入的起始IP地址无效（请输入点分十进制格式的有效IP！\n");
        exit(1);
    }
    if (inet_addr(argv[2]) == INADDR_NONE) {
        printf("输入的结束IP地址无效（请输入点分十进制格式的有效IP！\n");
        exit(1);
    }
    // 将ip地址转换成自己定义的类
    ip_adr st(argv[1]);
    ip_adr ed(argv[2]);
    if (st > ed) {  // 比较ip地址大小
        printf("输出的结束IP地址大于开始IP地址！\n");
    }

    WSADATA wsa;                       // Windows异步套接字
    WSAStartup(MAKEWORD(2, 2), &wsa);  // WSA 2.2 启动

    while (1) {
        if (st > ed)
            break;                               // 搜完结束
        u_long ip2f = inet_addr(st.adr2char());  // 获取当前搜索ip
        if (ip2f == INADDR_NONE) {
            break;
        }
        printf("\n正在扫描IP：");
        st.print();         // 输出当前搜索的ip地址
        try_connect(ip2f);  // 尝试搜索
        st.add();           // ip地址+1
    }

    WSACleanup();

    printf("\n扫描结束！\n");
}