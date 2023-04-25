#pragma comment(lib, "Ws2_32.lib")
#pragma once

#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>

// 构造ICMP回显请求消息，并以TTL递增的顺序发送报文
// ICMP类型字段
const BYTE ICMP_ECHO_REQUEST = 8;  // 请求回显
const BYTE ICMP_ECHO_REPLY = 0;    // 回显应答

// 其他常量定义
const int ICMP_DATA_SIZE = 32;          // ICMP报文默认数据字段长度
const int MAX_ICMP_PACKET_SIZE = 1024;  // 接受缓冲区大小
const int MAX_TRY_TIMES = 4;            // 最大尝试次数

// ICMP报头
struct ICMP_HEADER {
    BYTE type : 8;      // 8位类型字段
    BYTE code : 8;      // 8位代码字段
    USHORT cksum : 16;  // 16位效验和
    USHORT id : 16;     // 16位标识符
    USHORT seq : 16;    // 16位序列号
};

// IP报头
struct IP_HEADER {
    unsigned char hdr_len : 4;           // 4位头部长度。单位为32比特的字
    unsigned char version : 4;           // 4位版本号。因为字节序不同，所以版本号在后面
    unsigned char tos : 8;               // 8位服务类型
    unsigned short total_len : 16;       // 16位总长度。单位为8比特字节
    unsigned short identifier : 16;      // 16位标识符
    unsigned short frag_and_flags : 16;  // 3位标志加13位片偏移
    unsigned char ttl : 8;               // 8位生存时间
    unsigned char protocol : 8;          // 8位上层协议号
    unsigned short checksum : 16;        // 16位效验和
    unsigned long sourceIP : 32;         // 32位源IP地址
    unsigned long destIP : 32;           // 32位目的IP地址
};

// 报文解码结构
struct DECODE_RESULT {
    USHORT SeqNo;         // 序列号
    DWORD RoundTripTime;  // 时间
    DWORD TotalTime;      // 累积时间（用于计算平均值
};

class ip_adr {
   public:
    int ip[4];

    ip_adr(char* x) {
        int st = 0;
        int ed = 0;
        int siz = strlen(x);
        while (ed < 4) {
            int tmp = 0;
            for (st; st < siz; ++st) {
                if (x[st] == '.') {
                    st++;
                    break;
                }
                tmp = tmp * 10 + x[st] - '0';
            }
            ip[ed] = tmp;
            ed++;
        }
    }

    void print() {
        printf("%s\n", adr2char());
    }

    bool operator>(const ip_adr& rhs) {
        for (int i = 0; i < 4; ++i) {
            if (ip[i] > rhs.ip[i])
                return true;
            if (ip[i] < rhs.ip[i])
                return false;
        }
        return false;
    }

    const char* adr2char() {
        std::string s = "";
        s += std::to_string(ip[0]);
        s += ".";
        s += std::to_string(ip[1]);
        s += ".";
        s += std::to_string(ip[2]);
        s += ".";
        s += std::to_string(ip[3]);
        return s.c_str();
    }

    ip_adr add() {
        ip[3]++;
        ip[2] += (ip[3] > 255);
        ip[3] = ip[3] > 255 ? 0 : ip[3];
        ip[1] += (ip[2] > 255);
        ip[2] = ip[2] > 255 ? 0 : ip[2];
        ip[0] += (ip[1] > 255);
        ip[1] = ip[1] > 255 ? 0 : ip[1];
        return *this;
    }
};

USHORT checksum(USHORT* buff, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buff++;
        size -= sizeof(USHORT);
    }
    // 是奇数
    if (size) {
        cksum += *(UCHAR*)buff;
    }
    // 将32位的chsum高16位和低16位相加，然后取反
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (USHORT)(~cksum);
}

BOOL DecodeIcmpResponse(char* pBuf, int iPacketSize, DECODE_RESULT& DecodeResult, BYTE ICMP_ECHO_REPLY, BYTE ICMP_TIMEOUT);
void try_connect(u_long ip2find);
