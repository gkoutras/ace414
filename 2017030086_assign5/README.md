# ACE414 Assignment 5

In this assignment, using the Packet Capture library (libpcap), a program was implemented using C, with following tasks:
1.  - Network traffic had to be monitored live from a network interface (pcap_open_live).
    - A given pcap file had to be read (pcap_open_offline).
2. Network traffic had to be captured and the incoming TCP and UDP packets had to be proccessed.

---

Processing of the pcap file data is done through the functions of the libpcap library. Specifically, via the `pcap_open_offline(pcap_file, err)` and `pcap_loop()` functions.

in order to count the network flows generated during packet capture, a struct was created with the five fields that define the flow according to its definition. That is Source IP and Port, Destination IP and Port and Transfer Layer Protocol (TCP or UDP), and a linked list of nodes in which the nodes were uniquely stored, to be later checked for duplicates.

For questions 10, 11 and 12 the following applies:

10) Knowing that a packet generally consists of a header and then the payload, in order to fing where the payload is located in memory, the address of the recieved packet is taken and in that address number, the header size is added. The resulting hexademical number is the address of the payload.

11) To understand if a TCP packet has been retransmitted the following must apply:

- Whether the packet is not kept-alive.
- Whether the payload has a size greater than 0, or whether the SYN or FIN flags have a value of 1.
- Whether the expected sequence number is greater than the packet sequence number.

    To check the above, a struct was created with fields network_flow in which each TCP packet, the TCP header of each packet and its payload are opened. Each TCP packet is stored in reverse in a list (so as to statistically minimize the number of callbacks for the search in it), and for each packet transmission, it is checked if the above conditions apply by comparing the fields of the TCP packet examined and all others that have been inserted into the list. With this technique, the cases of TCP Fast Retransmission and TCP Spurious Retransmission are not taken into consideration. Results seem odd, as more packets are marked as retransmitted than they should be.

12) A UDP packet does not behave like a TCP when it comes to packet retransmission. It is impossible to detect a retransmitted UDP packet.
