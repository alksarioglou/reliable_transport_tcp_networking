# Reliable Transport Networking Project
Implementing the Go-Back-N reliable transport protocol capable of sending binary data over unreliable IP networks along with extensions such as Selective Repeat, Selective Acknowledgement and Congestion Control using **Python**\
Performed in teams of 3 people, where each team had to solve the task on a Virtual Machine

## Project Objectives
The objective of this project was to **implement a TCP-like reliable transport protocol capable of sending binary data over unreliable IP networks.**\
The protocol that was implemented during this project was the **Go-Back-N Protocol** as used in TCP today.\
Additional extensions were successfully added to enhance time efficiency but also resilience of the protocol. Such extensions included:
- **Selective Repeat** -> the receiver buffers out-of-order segments and delivers them to the application when missing segments are received, the sender only re-sends the next unacknowledged segment and only this one upon the reception of 3 duplicate acknowledgments
- **Selective Acknowledgment** -> the receiver informs the sender about blocks of consecutive packets that it received correctly in a special type of header, the sender re-transmits all the unacknowledged packets that fall outside of the boundaries of the contiguous blocks by using its buffer of transmitted but not yet acknowledged segments
- **Congestion Control** -> the sender adjusts its sending window according to the congestion window, which depends on the network congestion, according to the duplicate ACKs and the timeouts that occur (slow-start phase and additive-increase-multiplicative-decrease)

