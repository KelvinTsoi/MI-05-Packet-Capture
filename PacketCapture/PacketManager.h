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

#define PATH                   "capture[%s].pcap"      /* File name to store capture information */
#define CAPTURE_LENGTH          4096                   /* Maximum length of Capture Packet */


//Monitoring Mode
typedef enum
{
    INTERFACE_AUTO = 0,
    INTERFACE_LOOP = 1,
}INTERFACE;

extern INTERFACE InterfaceMonitored;

class PacketManager
{
public:

    /**
     * Summary: Start Capture Entrance
     * Parameters:
     *  mode: Differentiate monitoring mode
     * Return: Return zero if function success, other values signify function error code
     */
    int StartCapture(INTERFACE mode);

    /**
     * Summary: Singleton Pattern
     * Return: Return a static pointer of Class PacketManager
     */
    static PacketManager* Instance();

protected:

    /**
     * Summary: Constructor
     */
    PacketManager();

private:

    static PacketManager* pThis;        /* A static pointer of Class PacketManager used for calling back*/

    /**
     * Summary: Call back function of [pcap_loop]
     * Parameters:
     *  user: Id of Packet
     *  packet_header: Head information of Packet
     *  packet_content: Content of Packet
     */
    void HandleProc(u_char * user, const struct pcap_pkthdr * packet_header, const u_char * packet_content);


    /**
     * Summary: Call back function of Semaphore
     * Parameters:
     *  sig: Signal value
     */
    void sigActProc(int sig);


    /**
     * Summary: Execution function of [pcap_loop]
     * Parameters:
     *  sig: Signal value
     */
    static void sigActCallBackProc(int sig);


    /**
     * Summary: Execute function of Semaphore
     * Parameters:
     *  user: Id of Packet
     *  packet_header: Head information of Packet
     *  packet_content: Content of Packet
     */
    static void HandleCallBackProc(u_char * user, const struct pcap_pkthdr * packet_header, const u_char * packet_content);

    static PacketManager* _instance;    /* A static pointer of Class PacketManager used for Singleton Pattern */

    /**
     * Summary: Get Current Time in static format
     * Parameters:
     *  gTime: String to store the time, use for preventing the repetition of file name
     */
    void GetDate(char* gTime);

private:

    struct sigaction act;           /* Semaphore Registration Information */

    char *device_name;              /* Store device name */
    char ebuf[PCAP_ERRBUF_SIZE];    /* Error Message */

    int cap_len;                    /* Capture data length */
    int dev_flag;                   /* Promiscuous mode */
    int dev_time;                   /* Set timeout */

    pcap_t *pd;                     /* Packet capture description words */

    struct bpf_program fcode;       /* Capturing rules */
    bpf_u_int32 netmaskp;           /* NetMask */
    bpf_u_int32 netp;               /* Network number */
    char *netmask;                  /* Transformed NetMask */
    char *net;                      /* Transformed Network number */
    struct in_addr addr;            /* As the transformation of excess */

    int pcap_link;                  /* Type of data link layer */

    pcap_dumper_t *pd_t;            /* File to save captured packets */
    pcap_t *pd_tp;                  /* File to open captured packets */
    FILE *pcapfile;                 /* File Pointer */
    int pcapno;                     /* File descriptor */

    struct pcap_stat stat;          /* Captured packet statistics */
};


#endif /* _PACKETMANAGER_H */

