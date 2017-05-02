/**************************************************************************
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
 * File:   PacketManager.h
 * Author: CAI
 * Created on 2017/5/2, 10:00pm
 */

#ifndef _PACKETMANAGER_H
#define _PACKETMANAGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include <pcap/pcap.h>

#define PATH                   "save.pcap"      /*  */
#define CAPTURE_LENGTH         4096
#define AUTO                   100
#define LOOP                   101


class PacketManager
{
public:

    int StartCapture(int mode);

    static PacketManager* Instance();

protected:

    PacketManager();

private:

    static PacketManager* pThis;

    void HandleProc(u_char * user, const struct pcap_pkthdr * packet_header, const u_char * packet_content);

    void sigActProc(int sig);

    static void sigActCallBackProc(int sig);

    static void HandleCallBackProc(u_char * user, const struct pcap_pkthdr * packet_header, const u_char * packet_content);

    static PacketManager* _instance;    /*  */

private:

    struct sigaction act;           /*  */

    char *device_name;              /*  */
    char ebuf[PCAP_ERRBUF_SIZE];    /*  */

    int pcap_net;

    int cap_len;                    /*  */
    int dev_flag;                   /*  */
    int dev_time;                   /*  */

    pcap_t *pd;                     /*  */

    struct bpf_program fcode;       /*  */
    bpf_u_int32 netmaskp;           /*  */
    bpf_u_int32 netp;               /*  */
    char *netmask;                  /*  */
    char *net;                      /*  */
    struct in_addr addr;            /*  */

    int pcap_link;                  /*  */

    pcap_dumper_t *pd_t;            /*  */
    pcap_t *pd_tp;                  /*  */
    FILE *pcapfile;                 /*  */
    int pcapno;                     /*  */

    struct pcap_stat stat;          /*  */
};


#endif /* _PACKETMANAGER_H */

