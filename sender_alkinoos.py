"""A Sender for the GBN protocol."""

# Disable pylint rules which are incompatible with our naming conventions
# pylint: disable=C0103,W0221,W0201,R0902,R0913,R0201

import argparse
import queue as que
import logging
from scapy.sendrecv import send
from scapy.config import conf
from scapy.layers.inet import IP, ICMP
from scapy.packet import Packet, bind_layers
from scapy.fields import (BitEnumField, BitField, ShortField, ByteField,
                          ConditionalField)
from scapy.automaton import Automaton, ATMT

FORMAT = "[SENDER:%(lineno)3s - %(funcName)10s()] %(message)s"
logging.basicConfig(format=FORMAT)
log = logging.getLogger('sender')
log.setLevel(logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

TIMEOUT = 1  # number of seconds before packets are retransmitted


class GBN(Packet):
    """The GBN Header.

    It includes the following fields:
        type: DATA or ACK
        options: sack support
        len: payload length
        hlen: header length
        num: sequence/ACK number
        win: sender/receiver window size
        blen: block length
        left_1: left edge of block 1
        length_1: length of block 1
        padd_2: padding
        left_2: left edge of block 2
        length_2: length of block 2
        padd_3: padding
        left_3: left edge of block 3
        length_3: length of block 3
    """
    name = 'GBN'
    fields_desc = [BitEnumField("type", 0, 1, {0: "data", 1: "ack"}),
                   BitField("options", 0, 7),
                   ShortField("len", None),
                   ByteField("hlen", 0),
                   ByteField("num", 0),
                   ByteField("win", 0),
                   ConditionalField(ByteField("blen", 0), lambda pkt:pkt.hlen >= 7),
                   ConditionalField(ByteField("left_1", 0), lambda pkt:pkt.hlen >= 8),
                   ConditionalField(ByteField("length_1", 0), lambda pkt:pkt.hlen >= 9),
                   ConditionalField(ByteField("padd_2", 0), lambda pkt:pkt.hlen >= 10),
                   ConditionalField(ByteField("left_2", 0), lambda pkt:pkt.hlen >= 11),
                   ConditionalField(ByteField("length_2", 0), lambda pkt:pkt.hlen >= 12),
                   ConditionalField(ByteField("padd_3", 0), lambda pkt:pkt.hlen >= 13),
                   ConditionalField(ByteField("left_3", 0), lambda pkt:pkt.hlen >= 14),
                   ConditionalField(ByteField("length_3", 0), lambda pkt:pkt.hlen >= 15)                   
                   ]


# GBN header is coming after the IP header
bind_layers(IP, GBN, frag=0, proto=222)


class GBNSender(Automaton):
    """Sender implementation for the GBN protocol using a Scapy automaton.

    Attributes:
        win: Maximum window size of the sender
        n_bits: number of bits used to encode sequence number
        receiver: IP address of the receiver
        sender: IP address of the sender
        q: Queue for all payload messages
        buffer: buffer to save sent but not acknowledged segments
        current: Sequence number of next data packet to send
        unack: First unacked segment
        receiver_win: Current window advertised by receiver, initialized with
                      sender window size
        Q_4_2: Is Selective Repeat used?
        SACK: Is SACK used?
        Q_4_4: Is Congestion Control used?
        count_acks: [indicates the number of repeated acks, indicates the ack number]
    """
    def parse_args(self, sender, receiver, n_bits, payloads, win,
                   Q_4_2, Q_4_3, Q_4_4, **kwargs):
        """Initialize Automaton."""
        Automaton.parse_args(self, **kwargs)
        self.win = win
        self.n_bits = n_bits
        assert self.win < 2**self.n_bits
        self.receiver = receiver
        self.sender = sender
        self.q = que.Queue()
        for item in payloads:
            self.q.put(item)

        self.buffer = {}
        self.current = 0
        self.unack = 0
        self.receiver_win = win
        self.Q_4_2 = Q_4_2
        self.SACK = Q_4_3
        # Make sure that not both SACK and Selective Repeat are used at the same time
        assert not(self.Q_4_2 and self.SACK)
        self.Q_4_4 = Q_4_4

        #count the same ACKs
        self.count_acks = [0, -1]

    def master_filter(self, pkt):
        """Filter packets of interest.

        Source has be the receiver and both IP and GBN headers are required.
        No ICMP packets.
        """
        return (IP in pkt and pkt[IP].src == self.receiver and GBN in pkt
                and ICMP not in pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        """Start state of the automaton."""
        raise self.SEND()

    @ATMT.state(final=1)
    def END(self):
        """End state of the automaton."""
        log.debug("All packets successfully transmitted!")

    @ATMT.state()
    def SEND(self):
        """Main state of sender.

        New packets are transmitted to the receiver as long as there is space
        in the window.
        """
        # check if you still can send new packets to the receiver
        if len(self.buffer) < min(self.win, self.receiver_win):
            try:
                # get next payload (automatically removes it from queue)
                payload = self.q.get(block=False)
                log.debug("Sending packet num: %s", self.current)

                # add the current segment to the buffer
                self.buffer[self.current] = payload
                log.debug("Current buffer size: %s", len(self.buffer))

                ###############################################################
                # TODO:                                                       #
                # create a GBN header with the correct header field values    #
                # send a packet to the receiver containing the created header #
                # and the corresponding payload                               #
                ###############################################################

                # create the GBN header for a packet
                # if SACK then options = '1'
                if (self.SACK):
                    header = GBN(type = "data", options = 1, len = len(payload), hlen = 6, num = self.current, win = self.win)
                else:
                    header = GBN(type = "data", options = 0, len = len(payload), hlen = 6, num = self.current, win = self.win)
                # send the packet
                send(IP(src = self.sender, dst = self.receiver)/header/payload)
                # sequence number of next packet
                self.current = int((self.current + 1) % 2**self.n_bits)

                # back to the beginning of the state
                # (send next packet if possible)
                raise self.SEND()

            # no more payload pieces in the queue --> if all are acknowledged,
            # we can end the sender
            except que.Empty:
                if self.unack == self.current:
                    raise self.END()

    @ATMT.receive_condition(SEND)
    def packet_in(self, pkt):
        """Transition: Packet coming in from the receiver"""
        log.debug("Received packet: %s", pkt.getlayer(GBN).num)
        raise self.ACK_IN(pkt)

    @ATMT.state()
    def ACK_IN(self, pkt):
        """State for received ACK."""
        # check if type is ACK
        if pkt.getlayer(GBN).type == 0:
            log.error("Error: data type received instead of ACK %s", pkt)
            raise self.SEND()
        else:
            log.debug("Received ACK %s", pkt.getlayer(GBN).num)

            # set the receiver window size to the received value
            self.receiver_win = pkt.getlayer(GBN).win

            ack = pkt.getlayer(GBN).num

            # Check if Receiver is using SACK otherwise deactivate it
            if (pkt.getlayer(GBN).options == 0):
                self.SACK = 0

            elif (pkt.getlayer(GBN).options == 1):
                self.SACK = 1

            #check if selective repeat needed and execute
            if self.Q_4_2 == 1:
                if ack == self.count_acks.__getitem__(1):
                    self.count_acks.__setitem__(0, self.count_acks.__getitem__(0)+1)
                    log.debug("Selective repeat counter: %s", self.count_acks.__getitem__(0) + 1)
                else:
                    self.count_acks.__setitem__(0, 0)
                    self.count_acks.__setitem__(1, ack)
                    log.debug("Selective repeat counter: %s", 1)
                #resend iff equals 3, but only the one missing packet
                if self.count_acks.__getitem__(0) >= 2:
                    log.debug("Selective repeat activated, resend packet %s", ack)
                    header = GBN(type="data", options=0, len=len(self.buffer[ack]), hlen=6, num=ack, win=self.win)
                    send(IP(src=self.sender, dst=self.receiver) / header / self.buffer[ack])
                    log.debug("Selective repeat finished")
                    self.count_acks.__setitem__(0, 0)
                    self.count_acks.__setitem__(1, -1)

            # Selective ACKnowledgements
            elif self.SACK == 1:

                # Declare a list which will reflect the ACKs received from the ranges in the received SACK packet
                rec_acks = []
                flat_rec_acks = [] # to combine all ranges for block length > 1

                # Different cases according to the block length

                # Block length 1
                if (pkt.getlayer(GBN).blen == 1):

                    # Create the reflection of the received ACKs in the list from the range received

                    # Deal with overflow first
                    if (pkt.getlayer(GBN).left_1 + pkt.getlayer(GBN).length_1 >= 2**self.n_bits):
                        rec_acks.append(range(pkt.getlayer(GBN).left_1, 2**self.n_bits))
                        rec_acks.append(range(0, pkt.getlayer(GBN).length_1 - len(range(pkt.getlayer(GBN).left_1, 2**self.n_bits))))
                    else: # Normal case
                        rec_acks.append(range(pkt.getlayer(GBN).left_1, pkt.getlayer(GBN).left_1 + pkt.getlayer(GBN).length_1))

                    # Make flat list of ranges
                    for i in range(len(rec_acks)):
                        for k in range(len(rec_acks[i])):
                            flat_rec_acks.append(rec_acks[i][k])

                    # Keep seq num of elements in sending buffer in a list
                    seq_numbers_send = list(self.buffer.keys())

                    # Specify seq num of last packet ACKed to set the limit for the retransmission window
                    # No retransmission allowed for packets after the last SACK block
                    final_index = seq_numbers_send.index((flat_rec_acks[-1]))

                    # Keep only the part of the sending buffer inside the allowed range set by the last ACKed packet in the SACK message
                    buffer_appl = seq_numbers_send[:final_index]

                    # Check all the seq nums in the allowed range of the sender buffer and retransmit only the ones
                    # that are not included in the received ACKs of the SACK message
                    for seqnum_appl in buffer_appl:
                        if (seqnum_appl not in flat_rec_acks):
                            log.debug("Sender SACK activated, resending packet %s", seqnum_appl)
                            header = GBN(type="data", options=1, len=len(self.buffer[seqnum_appl]), hlen=6, num=seqnum_appl, win=self.win)
                            send(IP(src=self.sender, dst=self.receiver) / header / self.buffer[seqnum_appl])
                    
                    log.debug("Sender SACK retransmit finished for block 1")


                # Block length 2
                if (pkt.getlayer(GBN).blen == 2):

                    # Create the reflection of the received ACKs in the list from the range received

                    # Deal with overflow first - Block 1
                    if (pkt.getlayer(GBN).left_1 + pkt.getlayer(GBN).length_1 >= 2**self.n_bits):
                        rec_acks.append(range(pkt.getlayer(GBN).left_1, 2**self.n_bits))
                        rec_acks.append(range(0, pkt.getlayer(GBN).length_1 - len(range(pkt.getlayer(GBN).left_1, 2**self.n_bits))))
                    else: # Normal case
                        rec_acks.append(range(pkt.getlayer(GBN).left_1, pkt.getlayer(GBN).left_1 + pkt.getlayer(GBN).length_1))

                    # Deal with overflow first - Block 2
                    if (pkt.getlayer(GBN).left_2 + pkt.getlayer(GBN).length_2 >= 2**self.n_bits):
                        rec_acks.append(range(pkt.getlayer(GBN).left_2, 2**self.n_bits))
                        rec_acks.append(range(0, pkt.getlayer(GBN).length_2 - len(range(pkt.getlayer(GBN).left_2, 2**self.n_bits))))
                    else: # Normal case
                        rec_acks.append(range(pkt.getlayer(GBN).left_2, pkt.getlayer(GBN).left_2 + pkt.getlayer(GBN).length_2))

                    # Make flat list of ranges
                    for i in range(len(rec_acks)):
                        for k in range(len(rec_acks[i])):
                            flat_rec_acks.append(rec_acks[i][k])

                    # Keep seq num of elements in sending buffer in a list
                    seq_numbers_send = list(self.buffer.keys())

                    # Specify seq num of last packet ACKed to set the limit for the retransmission window
                    # No retransmission allowed for packets after the last SACK block
                    final_index = seq_numbers_send.index((flat_rec_acks[-1]))

                    # Keep only the part of the sending buffer inside the allowed range set by the last ACKed packet in the SACK message
                    buffer_appl = seq_numbers_send[:final_index]

                    # Check all the seq nums in the allowed range of the sender buffer and retransmit only the ones
                    # that are not included in the received ACKs of the SACK message
                    for seqnum_appl in buffer_appl:
                        if (seqnum_appl not in flat_rec_acks):
                            log.debug("Sender SACK activated, resending packet %s", seqnum_appl)
                            header = GBN(type="data", options=1, len=len(self.buffer[seqnum_appl]), hlen=6, num=seqnum_appl, win=self.win)
                            send(IP(src=self.sender, dst=self.receiver) / header / self.buffer[seqnum_appl])
                    
                    log.debug("Sender SACK retransmit finished for blocks 1,2")

                # Block length 3
                if (pkt.getlayer(GBN).blen == 3):

                    # Create the reflection of the received ACKs in the list from the range received

                    # Deal with overflow first - Block 1
                    if (pkt.getlayer(GBN).left_1 + pkt.getlayer(GBN).length_1 >= 2**self.n_bits):
                        rec_acks.append(range(pkt.getlayer(GBN).left_1, 2**self.n_bits))
                        rec_acks.append(range(0, pkt.getlayer(GBN).length_1 - len(range(pkt.getlayer(GBN).left_1, 2**self.n_bits))))
                    else: # Normal case
                        rec_acks.append(range(pkt.getlayer(GBN).left_1, pkt.getlayer(GBN).left_1 + pkt.getlayer(GBN).length_1))

                    # Deal with overflow first - Block 2
                    if (pkt.getlayer(GBN).left_2 + pkt.getlayer(GBN).length_2 >= 2**self.n_bits):
                        rec_acks.append(range(pkt.getlayer(GBN).left_2, 2**self.n_bits))
                        rec_acks.append(range(0, pkt.getlayer(GBN).length_2 - len(range(pkt.getlayer(GBN).left_2, 2**self.n_bits))))
                    else: # Normal case
                        rec_acks.append(range(pkt.getlayer(GBN).left_2, pkt.getlayer(GBN).left_2 + pkt.getlayer(GBN).length_2))

                    # Deal with overflow first - Block 3
                    if (pkt.getlayer(GBN).left_3 + pkt.getlayer(GBN).length_3 >= 2**self.n_bits):
                        rec_acks.append(range(pkt.getlayer(GBN).left_3, 2**self.n_bits))
                        rec_acks.append(range(0, pkt.getlayer(GBN).length_3 - len(range(pkt.getlayer(GBN).left_3, 2**self.n_bits))))
                    else: # Normal case
                        rec_acks.append(range(pkt.getlayer(GBN).left_3, pkt.getlayer(GBN).left_3 + pkt.getlayer(GBN).length_3))

                    # Make flat list of ranges
                    for i in range(len(rec_acks)):
                        for k in range(len(rec_acks[i])):
                            flat_rec_acks.append(rec_acks[i][k])

                    # Keep seq num of elements in sending buffer in a list
                    seq_numbers_send = list(self.buffer.keys())

                    # Specify seq num of last packet ACKed to set the limit for the retransmission window
                    # No retransmission allowed for packets after the last SACK block
                    final_index = seq_numbers_send.index((flat_rec_acks[-1]))

                    # Keep only the part of the sending buffer inside the allowed range set by the last ACKed packet in the SACK message
                    buffer_appl = seq_numbers_send[:final_index]

                    # Check all the seq nums in the allowed range of the sender buffer and retransmit only the ones
                    # that are not included in the received ACKs of the SACK message
                    for seqnum_appl in buffer_appl:
                        if (seqnum_appl not in flat_rec_acks):
                            log.debug("Sender SACK activated, resending packet %s", seqnum_appl)
                            header = GBN(type="data", options=1, len=len(self.buffer[seqnum_appl]), hlen=6, num=seqnum_appl, win=self.win)
                            send(IP(src=self.sender, dst=self.receiver) / header / self.buffer[seqnum_appl])
                    
                    log.debug("Sender SACK retransmit finished for blocks 1,2,3")


            ################################################################
            # TODO:                                                        #
            # remove all the acknowledged sequence numbers from the buffer #
            # make sure that you can handle a sequence number overflow     #
            ################################################################

            # the sequence number of in the ACK packet is the next unacknowledged
            # packet
            self.unack = ack

            # when a ack is received, all packets from the window can be removed
            # from the buffer
            for i in range(1, self.receiver_win+1):
                # to handle a sequence number overflow, the maximum sequence number

                # might have to be added
                if(ack-i>=0):
                    self.buffer.pop(ack-i, None)
                else:
                    self.buffer.pop(ack-i%self.receiver_win+2**self.n_bits-1, None)

        # back to SEND state
        raise self.SEND()

    @ATMT.timeout(SEND, TIMEOUT)
    def timeout_reached(self):
        #set selective repeat to 0
        self.count_acks.__setitem__(0, 0)
        self.count_acks.__setitem__(1, -1)
        """Transition: Timeout is reached for first unacknowledged packet."""
        log.debug("Timeout for sequence number %s", self.unack)
        raise self.RETRANSMIT()

    @ATMT.state()
    def RETRANSMIT(self):
        """State for retransmitting packets."""

        ##############################################
        # TODO:                                      #
        # retransmit all the unacknowledged packets  #
        # (all the packets currently in self.buffer) #
        ##############################################
        #go through the buffer, create a header for each element and retransmit it

        
        for seqnum in self.buffer:
            
            # Check if SACK is used and change the 'options' field accordingly
            if (self.SACK):
                header = GBN(type = "data", options = 1, len = len(self.buffer[seqnum]), hlen = 6, num = seqnum, win = self.win)
                send(IP(src = self.sender, dst = self.receiver)/header/self.buffer[seqnum])
            else:
                header = GBN(type = "data", options = 0, len = len(self.buffer[seqnum]), hlen = 6, num = seqnum, win = self.win)
                send(IP(src = self.sender, dst = self.receiver)/header/self.buffer[seqnum])




        # back to SEND state
        raise self.SEND()


if __name__ == "__main__":
    # get input arguments
    parser = argparse.ArgumentParser('GBN sender')
    parser.add_argument('sender_IP', type=str,
                        help='The IP address of the sender')
    parser.add_argument('receiver_IP', type=str,
                        help='The IP address of the receiver')
    parser.add_argument('n_bits', type=int,
                        help='The number of bits used to encode the sequence '
                             'number field')
    parser.add_argument('input_file', type=str,
                        help='Path to the input file')
    parser.add_argument('window_size', type=int,
                        help='The window size of the sender')
    parser.add_argument('Q_4_2', type=int,
                        help='Use Selective Repeat (question 4.2)')
    parser.add_argument('Q_4_3', type=int,
                        help='Use Selective Acknowledgments (question 4.3)')
    parser.add_argument('Q_4_4', type=int,
                        help='Use Congestion Control (question 4.4/Bonus)')
    parser.add_argument('--interface', type=str, help='(optional) '
                        'interface to listen on')

    args = parser.parse_args()

    if args.interface:
        conf.iface = args.interface

    bits = args.n_bits
    assert bits <= 8

    in_file = args.input_file
    # list for binary payload
    payload_to_send_bin = list()
    # chunk size of payload
    chunk_size = 2**6

    # fill payload list
    with open(in_file, "rb") as file_in:
        while True:
            chunk = file_in.read(chunk_size)
            if not chunk:
                break
            payload_to_send_bin.append(chunk)

    # initial setup of automaton
    GBN_sender = GBNSender(args.sender_IP, args.receiver_IP, bits,
                           payload_to_send_bin, args.window_size, args.Q_4_2,
                           args.Q_4_3, args.Q_4_4)

    # start automaton
    GBN_sender.run()

