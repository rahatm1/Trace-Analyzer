Build with:
    `$ make`
Run with:
    `$ ./trace_analyzer capfile`

# Program Architecture
The program architecture is very simple. A filter is used to only keep UDP (and ICMP)
packets. The packets are searched through for a packet sent with TTL = 1. This is the
first packet that the traceroute sent from the source. The source and destination of
this packet is the source and ultimate destination node, respectively.

Next, all the packets are filtered by ICMP TTL exceeded. Since ICMP TTL exceeded
are only sent by intermediary hops, all the source addresses are stored in an
array called hops. Next a for loop over this array prints all the intermediate hops.

To find the protocol headers, a boolean array of 256 size is used since there can
be only 0 to 255 value. All the packets are looped using the initial filter
and if a protocol header is found, that entry is matched and the boolean value at
that position is set to true. Since, it is know that ICMP and UDP has the value of
1 and 17 respectively, their names are printed. For any other protocol header that
may have appeared, only the numbers are printed.

If fragmentation occurs during a traceroute every increment of TTL UDP/ICMP
packet should have the same number of fragments. So, the sent packets
are filtered using the source and ultimate destination address. These packets
are checked for the MF flag and numFragment variable is incremented for every match,
meaning that there are more fragments until there are no MF flag. Then, the offset
at that packet is read and saved at lastFragOffset.

To find the average RTT and standard deviation, an ICMP/UDP packet is searched
for with TTL = X where X is incremented one by one and the starttime for this packet (or all fragments)
are saved. Two different approaches are taken for windows and linux. For windows,
the packets are filtered by icmp echo request and they are matched with their corresponding
icmp identifier and echo request.

***BONUS:***
Due to the issue mentioned for linux in the assignment, the source and destination
port of sent and received UDP packets for every TTL increment are matched.

Finally, simple time difference function is used to calculate the time difference
from the endtime and the starttime (or all its fragment individually). Then,
the average and standard deviation is calculated with their respective formula.

***Note:***
Only first traceroute (or TTL=X and TTL exceeded group) is used.
If a request from a traceroute doesn't have a reply, that hop is simply ignored.
