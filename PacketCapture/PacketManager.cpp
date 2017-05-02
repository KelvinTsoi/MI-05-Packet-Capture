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

void PacketManager::HandleProc(u_char * user, const struct pcap_pkthdr * packet_header, const u_char * packet_content)
{
    pcap_dump(user, packet_header, packet_content);
    printf("Packet Got!\n");
}

void PacketManager::sigActCallBackProc(int sig)
{
    if(!pThis)
        return;
    pThis->sigActProc(sig);
}

void PacketManager::sigActProc(int sig)
{
    if (pcap_stats(pd, &stat))
        printf("pcap_stat error\n");
    printf("recv:%d, drop:%d,not support:%d\n", stat.ps_recv, stat.ps_drop, stat.ps_ifdrop);

    pcap_dump_flush(pd_t);

    if (NULL == (pd_tp = pcap_open_offline(PATH, ebuf)))
        printf("pcap_dumper_t error\n");

    pcapfile = pcap_file(pd_tp);

    pcapno = pcap_fileno(pd_tp);

    printf("byte-order:%d\n", pcap_is_swapped(pd_tp));

    pcap_close(pd);
    pcap_dump_close(pd_t);

    exit(0);
}

int PacketManager::StartCapture(int mode)
{
    cap_len = CAPTURE_LENGTH;
    dev_flag = 1;
    dev_time = 1000;

    act.sa_handler = sigActCallBackProc;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, 0);

    if (AUTO == mode)
    {
        device_name = pcap_lookupdev(ebuf);
        if (NULL == device_name)
            printf("pcap_lookupdev error\n");
        else
            printf("device is %s\n", device_name);
    }
    else
        device_name = (char *)"lo";

    pcap_net = pcap_lookupnet(device_name, &netp, &netmaskp, ebuf);
    if (-1 == (pcap_net))
        printf("pcap_net error\n");

    addr.s_addr = netp;
    net = inet_ntoa(addr);
    printf("net is:%s\n", inet_ntoa(addr));

    addr.s_addr = netmaskp;
    netmask = inet_ntoa(addr);
    printf("netmask is:%s\n", inet_ntoa(addr));

    pd = pcap_open_live(device_name, cap_len, dev_flag, dev_time, ebuf);
    if (NULL == pd)
        printf("pcap_open_live error\n");

    pcap_link = pcap_datalink(pd);
    printf("now the datalink is:%d\n", pcap_link);

    int real_cap_len = pcap_snapshot(pd);
    printf("largest capture bytes:%d\n", real_cap_len);

    if (NULL == (pd_t = pcap_dump_open(pd, PATH)))
        printf("pcap_dump_open error\n");

    netmask = 0;
    if (pcap_compile(pd, &fcode, NULL, 1, netmaskp) < 0)
        printf("pcap_compile error\n");

    if (pcap_setfilter(pd, &fcode) < 0)
        printf("pcap_setfilter error\n");

    if (pcap_loop(pd, -1, HandleCallBackProc, (u_char*) pd_t) < 0)
        printf("pcap_loop error\n");

    return 0;
}

