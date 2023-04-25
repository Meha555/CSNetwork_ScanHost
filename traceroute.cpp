// traceroute.cpp
/*----------------------------------------------------------
功能说明：
    该程序简单实现了Windows操作系统的tracert命令功能，
    可以输出IP报文从本机出发到达目的主机所经过的路由信息。
-----------------------------------------------------------*/
#include "traceroute.h"
#include <stdio.h>
#include <iomanip>
#include <iostream>
using namespace std;

int main(int argc, char* argv[]) {
    while (true) {
        /*存放 IP*/
        char ipString[100];
        cout << "TraceRoute:";
        scanf("%s", ipString);
        // char *ipString = "www.baidu.com";

        /*初始化winsock2环境*/
        WSADATA wsa;                                // 一种数据结构。这个结构被用来存储被WSAStartup函数调用后返回的Windows Sockets数据
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)  // 进行相应的socket库绑定,MAKEWORD(2,2)表示使用WINSOCK2版本
        {
            cerr << "\nFailed to initialize the WinSock2 DLL\n"
                 << "error code: " << WSAGetLastError() << endl;  // Cerr通常用于输出错误信息与其他不属于正常逻辑的输出内容
            return -1;
        }

        /*将命令行参数转换为IP地址*/
        u_long ulDestIP = inet_addr(ipString);  // 将一个点分十进制的IP转换成一个长整数型数（u_long类型）

        // cout<<"测试————"<<"长整型数"<<ulDestIP<<endl;
        if (ulDestIP == INADDR_NONE)  // INADDR_NONE 是个宏定义，代表IpAddress 无效的IP地址。
        {
            // 转换不成功时按域名解析
            hostent* pHostent = gethostbyname(ipString);  // 返回对应于给定主机名的包含主机名字和地址信息的hostent结构的指针
            if (pHostent) {
                ulDestIP = (*(in_addr*)pHostent->h_addr).s_addr;  // in_addr 用来表示一个32位的IPv4地址.            /cout<<"测试————"<<"ip地址"<<ulDestIP<<endl;

                // 输出屏幕信息
                cout << "\nTracing route to " << ipString
                     << " [" << inet_ntoa(*(in_addr*)(&ulDestIP)) << "]"  // 将网络地址转换成“.”点隔的字符串格式
                     << " with a maximum of " << DEF_MAX_HOP << " hops.\n"
                     << endl;  // DEF_MAX_HOP 最大跳站数
            } else             // 解析主机名失败
            {
                cerr << "\nCould not resolve the host name " << ipString << '\n'
                     << "error code: " << WSAGetLastError() << endl;
                WSACleanup();  // 终止Winsock 2 DLL (Ws2_32.dll) 的使用
                return -1;
            }
        } else {
            // 输出屏幕信息
            cout << "Tracing route to " << ipString
                 << " with a maximum of " << DEF_MAX_HOP << " hops." << endl;
        }
        // 填充目的Socket地址
        // struct sockaddr_in Lewis;
        //   Lewis.sin_family      = AF_INET;//表示地址类型，对于基于TCP/IP传输协议的通信，该值只能是AF_INET；
        //   Lewis.sin_port        = htons(80);//表示端口号，例如：21 或者 80
        //   Lewis.sin_addr.s_addr = inet_addr("202.96.134.133");//表示32位的IP地址
        //   memset(Lewis.sin_zero,0,sizeof(Lewis.sin_zero));//表示填充字节

        sockaddr_in destSockAddr;                        // 用来处理网络通信的地址
        ZeroMemory(&destSockAddr, sizeof(sockaddr_in));  // 用0来填充一块内存区域
        destSockAddr.sin_family = AF_INET;               // sin_family;//地址族  协议簇 AF_INET（TCP/IP – IPv4）
        destSockAddr.sin_addr.s_addr = ulDestIP;         // s_addr 32位IPv4地址
        // 使用ICMP协议创建Raw Socket
        SOCKET sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);  // 套接字类型：原始套接字，IPPROTO_ICMP表示ICMP报头由程序构造，iFlags：套接口属性描述
        if (sockRaw == INVALID_SOCKET)                                                              // 无效套接字
        {
            cerr << "\nFailed to create a raw socket\n"
                 << "error code: " << WSAGetLastError() << endl;
            WSACleanup();
            return -1;
        }
        // 设置端口属性
        int iTimeout = DEF_ICMP_TIMEOUT;  // 3000ms
        // cout<<"测试————"<<"TIMEOUT:"<<iTimeout<<endl;
        if (setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&iTimeout, sizeof(iTimeout)) == SOCKET_ERROR)
        // 设置与某个套接字关联的选 项。选项可能存在于多层协议中,为了操作套接字层的选项，应该 将层的值指定为SOL_SOCKET
        // 将要被设置或者获取选项的套接字,选项所在的协议层,需要访问的选项名(套接字的操作都自动带有超时时间),指向包含新选项值的缓冲,现选项的长度
        {
            cerr << "\nFailed to set recv timeout\n"
                 << "error code: " << WSAGetLastError() << endl;
            closesocket(sockRaw);
            WSACleanup();
            return -1;
        }
        // 创建ICMP包发送缓冲区和接收缓冲区
        char IcmpSendBuf[sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE];
        memset(IcmpSendBuf, 0, sizeof(IcmpSendBuf));
        char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE];
        memset(IcmpRecvBuf, 0, sizeof(IcmpRecvBuf));
        // 填充待发送的ICMP包（头和数据部分）
        ICMP_HEADER* pIcmpHeader = (ICMP_HEADER*)IcmpSendBuf;
        pIcmpHeader->type = ICMP_ECHO_REQUEST;
        pIcmpHeader->code = 0;
        pIcmpHeader->id = (USHORT)GetCurrentProcessId();
        memset(IcmpSendBuf + sizeof(ICMP_HEADER), 'E', DEF_ICMP_DATA_SIZE);  // 数据部分填充
        // 开始探测路由
        DECODE_RESULT stDecodeResult;
        BOOL bReachDestHost = FALSE;
        USHORT usSeqNo = 0;
        int iTTL = 1;
        int iMaxHop = DEF_MAX_HOP;
        while (!bReachDestHost && iMaxHop--) {
            // 设置IP数据报头的ttl字段
            setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char*)&iTTL, sizeof(iTTL));  // 为0（IPPROTO_IP)的raw socket。用于接收任何的IP数据包。其中的校验和和协议分析由程序自己完成。
            // 输出当前跳站数作为路由信息序号
            cout << setw(3) << iTTL << flush;  // setw(3)设置域宽，cout<<flush表示将缓冲区的内容马上送进cout，把输出缓冲区刷新。
            // 填充ICMP数据报剩余字段
            ((ICMP_HEADER*)IcmpSendBuf)->cksum = 0;
            ((ICMP_HEADER*)IcmpSendBuf)->seq = htons(usSeqNo++);  // 将无符号短整型主机字节序转换为网络字节序,将一个数的高低位互换, (如:12 34 --> 34 12)
            ((ICMP_HEADER*)IcmpSendBuf)->cksum = GenerateChecksum((USHORT*)IcmpSendBuf, sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE);

            // 记录序列号和当前时间
            stDecodeResult.usSeqNo = ((ICMP_HEADER*)IcmpSendBuf)->seq;
            stDecodeResult.dwRoundTripTime = GetTickCount();  // 返回从操作系统启动到当前所经过的毫秒数，常常用来判断某个方法执行的时间

            // 发送ICMP的EchoRequest数据报
            if (sendto(sockRaw, IcmpSendBuf, sizeof(IcmpSendBuf), 0, (sockaddr*)&destSockAddr, sizeof(destSockAddr)) == SOCKET_ERROR) {
                // 如果目的主机不可达则直接退出
                if (WSAGetLastError() == WSAEHOSTUNREACH)
                    cout << "/t" << "Destination host unreachable.\n"
                         << "\nTrace complete.\n"
                         << endl;
                closesocket(sockRaw);
                WSACleanup();
                return 0;
            }
            // 接收ICMP的EchoReply数据报
            // 因为收到的可能并非程序所期待的数据报，所以需要循环接收直到收到所要数据或超时
            sockaddr_in from;
            int iFromLen = sizeof(from);
            int iReadDataLen;
            while (true) {
                // 等待数据到达
                iReadDataLen = recvfrom(sockRaw, IcmpRecvBuf, MAX_ICMP_PACKET_SIZE, 0, (sockaddr*)&from, &iFromLen);
                if (iReadDataLen != SOCKET_ERROR)  // 有数据包到达
                {
                    // 解码得到的数据包，如果解码正确则跳出接收循环发送下一个EchoRequest包
                    if (DecodeIcmpResponse(IcmpRecvBuf, iReadDataLen, stDecodeResult)) {
                        if (stDecodeResult.dwIPaddr.s_addr == destSockAddr.sin_addr.s_addr)
                            bReachDestHost = TRUE;
                        cout << '\t' << inet_ntoa(stDecodeResult.dwIPaddr) << endl;  // 将网络地址转换成“.”点隔的字符串格式
                        break;
                    }
                } else if (WSAGetLastError() == WSAETIMEDOUT)  // 接收超时，打印星号
                {
                    cout << setw(9) << '*' << '\t' << "Request timed out." << endl;
                    break;
                } else {
                    cerr << "\nFailed to call recvfrom\n"
                         << "error code: " << WSAGetLastError() << endl;
                    closesocket(sockRaw);
                    WSACleanup();
                    return -1;
                }
            }
            // TTL值加1
            iTTL++;
            // cout<<"测试————"<<iTTL<<endl;
        }
        // 输出屏幕信息
        cout << "\nTrace complete.\n"
             << endl;
        closesocket(sockRaw);
        WSACleanup();
    }
    return 0;
}
/*产生网际校验和*/
USHORT GenerateChecksum(USHORT* pBuf, int iSize)  // 16
{
    unsigned long cksum = 0;  // 32
    while (iSize > 1)         // 40
    {
        cksum += *pBuf++;
        iSize -= sizeof(USHORT);
    }
    if (iSize)
        cksum += *(UCHAR*)pBuf;  // 8
    // printf("测试——cksum——测试：%x\n",cksum);
    // printf("测试——cksum>>16——测试：%x\n",cksum>>16);
    // printf("测试——cksum & 0xffff——测试：%x\n",cksum & 0xffff);
    cksum = (cksum >> 16) + (cksum & 0xffff);
    // printf("测试——cksum——测试：%x\n",cksum);
    // printf("测试——cksum>>16——测试：%x\n",cksum>>16);
    cksum += (cksum >> 16);
    // printf("测试——cksum——测试：%x\n",cksum);
    // printf("测试——(USHORT)(~cksum)——测试：%x\n",(USHORT)(~cksum));
    return (USHORT)(~cksum);  //~ 按位取反
}

/*解码得到的数据报*/
BOOL DecodeIcmpResponse(char* pBuf, int iPacketSize, DECODE_RESULT& stDecodeResult) {
    // 检查数据报大小的合法性
    IP_HEADER* pIpHdr = (IP_HEADER*)pBuf;
    int iIpHdrLen = pIpHdr->hdr_len * 4;  // 单位4个字节
    if (iPacketSize < (int)(iIpHdrLen + sizeof(ICMP_HEADER)))
        return FALSE;
    // 按照ICMP包类型检查id字段和序列号以确定是否是程序应接收的Icmp包
    ICMP_HEADER* pIcmpHdr = (ICMP_HEADER*)(pBuf + iIpHdrLen);
    USHORT usID, usSquNo;  // ICMP头 标识符和序列号
    if (pIcmpHdr->type == ICMP_ECHO_REPLY) {
        usID = pIcmpHdr->id;
        usSquNo = pIcmpHdr->seq;
    } else if (pIcmpHdr->type == ICMP_TIMEOUT) {
        char* pInnerIpHdr = pBuf + iIpHdrLen + sizeof(ICMP_HEADER);                 // 载荷中的IP头
        int iInnerIPHdrLen = ((IP_HEADER*)pInnerIpHdr)->hdr_len * 4;                // 载荷中的IP头长
        ICMP_HEADER* pInnerIcmpHdr = (ICMP_HEADER*)(pInnerIpHdr + iInnerIPHdrLen);  // 载荷中的ICMP头
        usID = pInnerIcmpHdr->id;
        usSquNo = pInnerIcmpHdr->seq;
    } else
        return FALSE;
    if (usID != (USHORT)GetCurrentProcessId() || usSquNo != stDecodeResult.usSeqNo)
        return FALSE;
    // 处理正确收到的ICMP数据报
    if (pIcmpHdr->type == ICMP_ECHO_REPLY ||
        pIcmpHdr->type == ICMP_TIMEOUT) {
        // 返回解码结果
        stDecodeResult.dwIPaddr.s_addr = pIpHdr->sourceIP;
        stDecodeResult.dwRoundTripTime = GetTickCount() - stDecodeResult.dwRoundTripTime;
        // 打印屏幕信息
        if (stDecodeResult.dwRoundTripTime)
            cout << setw(6) << stDecodeResult.dwRoundTripTime << " ms" << flush;
        else
            cout << setw(6) << "<1"
                 << " ms" << flush;
        return TRUE;
    }
    return FALSE;
}