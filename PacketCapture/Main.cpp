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
 * File:   Main.cpp
 * Author: CAI
 * Created on 2017/5/2, 10:00pm
 */

#include "PacketManager.h"

#define SOFTWARE_VERSION    "1.0.01"

void PrintUsage(int argc, char** argv)
{
    char DTChar[100] = {0};

    if (argc == 2)
    {
        strcpy(DTChar, argv[1]);
        if (!strcasecmp(DTChar, "--help"))
        {
            printf("Usage: packetcapture --[option]\r\n");
            printf("Example1: packetcapture --auto\r\n");
            printf("Example2: packetcapture --loop\r\n");
            exit(1);
        }
    }
}

void PrintHelp()
{
    printf("Invalid argument, optional parameters:\r\n");
    printf("--help Usage Information\r\n");
    printf("--version  Version Information\r\n");
    exit(1);
}


void PrintVersionInfo(int argc, char** argv)
{
    char DTChar[100] = {0};
    if (argc == 2)
    {
        strcpy(DTChar, argv[1]);
        if (!strcasecmp(DTChar, "--version"))
        {
            char date[32] = __DATE__;
            struct tm t;
            memset(&t, 0, sizeof (t));
            strptime(date, "%b %d %Y", &t);
            t.tm_mon += 1;
            printf("\r\n"
                   "Application Name: packetcapture\r\n"
                   "Application Version: %s\r\n"
                   "Compile Date: %04d-%02d-%2d %s\r\n"
                   "\r\n",
                   SOFTWARE_VERSION, t.tm_year + 1900, t.tm_mon, t.tm_mday, __TIME__);
            exit(0);
        }
    }
}

int main(int argc, char** argv)
{
    if (geteuid() != 0)
    {
        fprintf(stderr, "Error: you must be root to run this program\r\n");
        exit(1);
    }

    if (argc < 2)
    {
        PrintHelp();
        exit(1);
    }
    else
    {
        PrintVersionInfo(argc, argv);
        PrintUsage(argc, argv);

        if (strcmp(argv[1], "--auto") == 0)
        {
            InterfaceMonitored = INTERFACE_AUTO;
        }
        else if (strcmp(argv[1], "--loop") == 0)
        {
            InterfaceMonitored = INTERFACE_LOOP;
        }
        else
        {
            PrintHelp();
            exit(1);
        }

        PacketManager::Instance()->StartCapture(InterfaceMonitored);
    }

    return 0;
}
