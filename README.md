# PersonalFirewall
a linux personal firewall

enviorment:
   Linux ubuntu 2.6.38-8-generic #42-Ubuntu SMP Mon Apr 11 03:31:24 UTC 2011 x86_64 x86_64 x86_64 GNU/Linux
   gcc version 4.5.2 (Ubuntu/Linaro 4.5.2-8ubuntu4)
   GNU Make 3.81

Build the module with "make"
Clean module (for new builds) with "make clean"

Load the module into kernel with "make load"
Unload the module from kernel with "make unload"

Use "dmesg" to see kernel info log.

gcc -o pf pf.c

pf Command:
Usage: sudo ./pf [In or Out] [Option][Detail][,Option][,Detail]
   or: ./pf --print
   or: ./pf --delete [Rule No.]

In or Out:
       --in                     control the incoming packet
       --out                    control the outgoing packet

Option:
   -s: --srcip                  set the source IP
   -m: --srcnetmask             set the source netmask
   -p: --srcport                set the source port
   -t: --destip                 set the destination IP
   -n: --destnetmask            set the destination netmask
   -q: --destport               set the destination port
   -c: --protocol               set the protocol
                                        ALL: all protocol
                                        TCP: TCP protocol
                                        UDP: UDP protocol
   -a: --action                 set the action
                                        BLOCK: block the packet
                                        UNBLOCK: unblock the packet

Print:
   -o: --print                  print the rule

Delete:
   -d: --delete                 delete the rule
