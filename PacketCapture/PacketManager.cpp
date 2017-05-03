/*/**************************************************************************
**
**	The author disclaims copyright to this source code.
** 	In place of a legal notice, here is a bless in:
**
**	May you do good and not evil.
**	May you find forgiveness for yourself and forgive others.
**	May you share freely, never taking more than you give.
**
*************************************************************************/

/*
 * File:   PacketManager.cpp
 * Author: CAI
 * Created on 2017/5/2, 10:00pm
 */

#include "PacketManager.h"

INTERFACE InterfaceMonitored;

PacketManager* PacketManager::_instance = NULL;

PacketManager* PacketManager::pThis = NULL;

PacketManager::PacketManager()
{
    pThis = this;
}

PacketManager* PacketManager::Instance()
{
	if (_instance == 0)
	{
		_instance = new PacketManager();
	}
	return _instance;
}

void PacketManager::HandleCallBackProc(u_char * user, const struct pcap_pkthdr * packet_header, const u_char * packet_content)
{
    if(!pThis)
        return;
    pThis->HandleProc(user, packet_header, packet_content);
}

void PacketManager::sigActCallBackProc(int sig)
{
    if(!pThis)
        return;
    pThis->sigActProc(sig);
}

void PacketManager::HandleProc(u_char * user, const struct pcap_pkthdr * packet_header, const u_char * packet_content)
{
    unsigned int * id = (unsigned int *)user;
    printf("\r\n"
           "Id[%u] Packet Length[%d] Number of Bytes[%d]\r\n",
           ++(*id), packet_header->len, packet_header->caplen
    );
    printf("Received Time %s", ctime((const time_t *)&packet_header->ts.tv_sec));
    printf("Content:\r\n");
    for(unsigned int i = 0; i < packet_header->len; ++i)
    {
        printf(" %02x", packet_content[i]);
        if( (i + 1) % 16 == 0 )
        {
            printf("\r\n");
        }
    }
    pcap_dump(user, packet_header, packet_content);
}

void PacketManager::sigActProc(int sig)
{
    if (pcap_stats(pd, &stat))
    {
        printf("pcap_stat error\n");
        exit(1);
    }
    printf("\r\nRecv:%d, Drop:%d, Not support:%d\r\n", stat.ps_recv, stat.ps_drop, stat.ps_ifdrop);

    pcap_dump_flush(pd_t);

    if (NULL == (pd_tp = pcap_open_offline(PATH, ebuf)))
    {
        printf("pcap_dumper_t error\n");
        exit(1);
    }

    pcapfile = pcap_file(pd_tp);

    pcapno = pcap_fileno(pd_tp);

    printf("Byte-order:%d\n", pcap_is_swapped(pd_tp));

    pcap_close(pd);
    pcap_dump_close(pd_t);

    exit(0);
}

int PacketManager::StartCapture(INTERFACE mode)
{
    cap_len = CAPTURE_LENGTH;
    dev_flag = 1;
    dev_time = 1000;

    act.sa_handler = sigActCallBackProc;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, 0);

    if (INTERFACE_AUTO == mode)
    {
        device_name = pcap_lookupdev(ebuf);
        if (NULL == device_name)
        {
            printf("pcap_lookupdev error\n");
            exit(1);
        }
        else
        {
            printf("Device is %s\n", device_name);
        }
    }
    else
        device_name = (char *)"lo";

    int pcap_net = pcap_lookupnet(device_name, &netp, &netmaskp, ebuf);
    if (-1 == (pcap_net))
    {
        printf("pcap_net error\n");
        exit(1);
    }

    addr.s_addr = netp;
    net = inet_ntoa(addr);
    printf("Net[%s]\r\n", inet_ntoa(addr));

    addr.s_addr = netmaskp;
    netmask = inet_ntoa(addr);
    printf("Net Mask[%s]\r\n", inet_ntoa(addr));

    pd = pcap_open_live(device_name, cap_len, dev_flag, dev_time, ebuf);
    if (NULL == pd)
    {
        printf("pcap_open_live error\r\n");
        exit(1);
    }

    pcap_link = pcap_datalink(pd);
    printf("Current Data Link[%d]\r\n", pcap_link);

    int real_cap_len = pcap_snapshot(pd);
    printf("Largest Capture Bytes[%d]\r\n", real_cap_len);

    char store_path[256] = {0x00};
    char getDateTime[128] = {0x00};
    GetDate(getDateTime);
    sprintf(store_path, PATH, getDateTime);
    if (NULL == (pd_t = pcap_dump_open(pd, store_path)))
    {
        printf("pcap_dump_open error\r\n");
        exit(1);
    }

    netmask = 0;
    if (pcap_compile(pd, &fcode, NULL, 1, netmaskp) < 0)
    {
        printf("pcap_compile error\r\n");
        exit(1);
    }

    if (pcap_setfilter(pd, &fcode) < 0)
    {
        printf("pcap_setfilter error\r\n");
        exit(1);
    }

    if (pcap_loop(pd, -1, HandleCallBackProc, (u_char*) pd_t) < 0)
    {
        printf("pcap_loop error\r\n");
        exit(1);
    }

    return 0;
}

void PacketManager::GetDate(char* gTime)
{
    time_t tim;
    struct tm *area;

    tim = time(NULL);
    area = localtime(&tim);

    memset(gTime, 0x00, sizeof(gTime));
    sprintf(gTime,
            "%04d-%02d-%02d-%02u-%02u-%02u",
            1900+area->tm_year, 1+area->tm_mon, area->tm_mday,
            area->tm_hour, area->tm_min, area->tm_sec
    );
    return;
}

