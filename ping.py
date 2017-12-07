#!/usr/bin/env python

import sys
import common


if __name__ == '__main__':
    # www.miit.gov.cn
    target = "202.106.121.6" #MIIT
    #target = "172.217.1.228" #Google
    #target = "34.228.54.77" #Test server

    myip = None
    if len(sys.argv) < 2:
        pass
    else:
        target = sys.argv[1]

    tr = common.PacketUtils(dst=target)
    print tr.ping(target)



