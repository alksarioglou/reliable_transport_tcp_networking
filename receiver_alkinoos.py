"""A Receiver for the GBN protocol."""

# Disable pylint rules which are incompatible with our naming conventions
# pylint: disable=C0103,W0221,W0201,R0902,R0913,R0201


import os
import random
import logging
import argparse
from scapy.sendrecv import send
from scapy.config import conf
from scapy.layers.inet import IP, ICMP
from scapy.packet import Packet, bind_layers
from scapy.fields import (BitEnumField, BitField, ShortField, ByteField,
                          ConditionalField)
from scapy.automaton import Automaton, ATMT


FORMAT = "   [RECEIVER:%(lineno)3s - %(funcName)12s()] %(message)s"
logging.basicConfig(format=FORMAT)
log = logging.getLogger('sender')
log.setLevel(logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# fixed random seed to reproduce packet loss
random.seed('TEST')


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
        left_1: left edge of 1st block
        length_1: length of 1st block
        padd_2: padding
        left_2: left edge of 2nd block
        length_2: length of 2nd block
        padd_3: padding
        left_3: left edge of 3rd block
        length_3: length of 3rd block
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


class GBNReceiver(Automaton):
    """Receiver implementation for the GBN protocol using a Scapy automaton.

    Attributes:
        win: Window size advertised by receiver
        n_bits: number of bits used to encode sequence number
        p_data: loss probability for data segments (0 <= p_data < 1)
        p_ack: loss probability for ACKs (0 <= p_ack < 1)
        sender: IP address of the sender
        receiver: IP address of the receiver
        next: Next expected sequence number
        out_file: Name of output file
        p_file: Expected payload size
        end_receiver: Can we close the receiver?
        end_num: Sequence number of last packet + 1
        buffer: contains buffered payloads that have been received out of order
        buffer_seq: contains the sequence number of the payloads in same order (?)
        buffer_size: indicates the current buffer size
    """

    def parse_args(self, receiver, sender, nbits, out_file, window, p_data,
                   p_ack, chunk_size, **kargs):
        """Initialize the automaton."""
        Automaton.parse_args(self, **kargs)
        self.win = window
        self.n_bits = nbits
        assert self.win <= 2**self.n_bits
        self.p_data = p_data
        assert p_data >= 0 and p_data < 1
        self.p_ack = p_ack
        assert p_ack >= 0 and p_ack < 1
        self.sender = sender
        self.receiver = receiver
        self.next = 0
        self.out_file = out_file
        self.p_size = chunk_size
        self.end_receiver = False
        self.end_num = -1
        """create empty buffer list and seq. number list"""
        self.buffer = []
        self.buffer_seq = []
        self.buffer_size = 0

    def master_filter(self, pkt):
        """Filter packets of interest.

        Source has be the sender and both IP and GBN headers are required.
        No ICMP packets.
        """
        return (IP in pkt and pkt[IP].src == self.sender and GBN in pkt
                and ICMP not in pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        """Start state of the automaton."""
        raise self.WAIT_SEGMENT()

    @ATMT.state(final=1)
    def END(self):
        """End state of the automaton."""
        log.debug("Receiver closed")

    @ATMT.state()
    def WAIT_SEGMENT(self):
        """Waiting state for new packets."""
        log.debug("Waiting for segment %s", self.next)

    @ATMT.receive_condition(WAIT_SEGMENT)
    def packet_in(self, pkt):
        """Transition: Packet is coming in from the sender."""
        raise self.DATA_IN(pkt)

    @ATMT.state()
    def DATA_IN(self, pkt):
        """State for incoming data."""
        num = pkt.getlayer(GBN).num
        payload = bytes(pkt.getlayer(GBN).payload)

        # received segment was lost/corrupted in the network
        if random.random() < self.p_data:
            log.debug("Data segment lost: [type = %s num = %s win = %s]",
                      pkt.getlayer(GBN).type,
                      num,
                      pkt.getlayer(GBN).win)
            raise self.WAIT_SEGMENT()

        # segment was received correctly
        else:
            log.debug("Received: [type = %s num = %s win = %s]",
                      pkt.getlayer(GBN).type,
                      num,
                      pkt.getlayer(GBN).win)

            # check if segment is a data segment
            ptype = pkt.getlayer(GBN).type
            if ptype == 0:

                # check if last packet --> end receiver
                if len(payload) < self.p_size:
                    self.end_receiver = True
                    self.end_num = (num + 1) % 2**self.n_bits

                # this is the segment with the expected sequence number
                if num == self.next:
                    log.debug("Packet has expected sequence number: %s", num)

                    # append payload (as binary data) to output file
                    with open(self.out_file, 'ab') as file:
                        file.write(payload)

                    log.debug("Delivered packet to upper layer: %s", num)

                    #log.debug("window size is: %s", self.win)

                    self.next = int((self.next + 1) % 2**self.n_bits)

                    #check buffer for buffered elements with correct sequence number
                    while self.buffer_size > 0:
                        if self.next in self.buffer_seq:
                            for itemSeq, item in zip(self.buffer_seq, self.buffer):
                                if itemSeq == self.next:
                                    log.debug("Delivered packet from buffer to upper layer: %s", itemSeq)
                                    with open(self.out_file, 'ab') as file_help:
                                        file_help.write(item)
                                    self.buffer_size -= 1
                                    self.buffer.remove(item)
                                    if itemSeq in self.buffer_seq:
                                        self.buffer_seq.remove(itemSeq)
                                    self.next = int((self.next + 1) % 2**self.n_bits)
                        else:
                            break

                # this was not the expected segment
                else:
                    log.debug("Out of sequence segment [num = %s] received. "
                              "Expected %s", num, self.next)
                    #log.debug("window size is %s", self.win)

                    #add to buffer iff doesn't exceed window size
                    firstElement = self.next + 1
                    lastElement = self.next + self.win - 1
                    if num < self.next:
                        firstElement = firstElement - 2**self.n_bits
                        lastElement = lastElement - 2**self.n_bits
                    if lastElement >= num >= firstElement:
                        if num not in self.buffer_seq:
                            self.buffer_size += 1
                            log.debug("Out of order sequence segment [num = %s] buffered. ", num)
                            self.buffer.append(payload)
                            self.buffer_seq.append(num)
            else:
                # we received an ACK while we are supposed to receive only
                # data segments
                log.error("ERROR: Received ACK segment: %s", pkt.show())
                raise self.WAIT_SEGMENT()

            # send ACK back to sender
            if random.random() < self.p_ack:
                # the ACK will be lost, discard it
                log.debug("Lost ACK: %s", self.next)

            # the ACK will be received correctly
            else:

                # If for sender options = '0', send normal ACK
                if (pkt.getlayer(GBN).options == 0):

                    header_GBN = GBN(type="ack",
                                     options=0,
                                     len=0,
                                     hlen=6,
                                     num=self.next,
                                     win=self.win)

                    log.debug("Sending ACK: %s", self.next)
                    send(IP(src=self.receiver, dst=self.sender) / header_GBN,
                         verbose=0)

                # If for sender options = '1', send SACK
                else:

                    # Variables for SACK
                    block_length = 0;
                    # Default value of header length is 6 bytes (no blocks to share with the sender)
                    header_length = 6;

                    # Variables for block 1
                    first_1 = 0;
                    len_1   = 0;

                    # Variables for block 2
                    first_2 = 0;
                    len_2   = 0;

                    # Variables for block 3
                    first_3 = 0;
                    len_3   = 0;

                    # Sort elements of the buffer_seq list in the correct numerical order and deal with overflow and reordering of segments received
                    under = [] # Values under max_value/2
                    over = []  # Values over max_value/2

                    max_value = 2**self.n_bits

                    # Separate seq nums to groups of bigger and smaller than the half maximum value
                    for i in self.buffer_seq:
                        if (i >= max_value/2):
                            over.append(i)
                        else:
                            under.append(i)

                    # Sort the lists produced above in numerical order
                    over_sorted = sorted(over)
                    under_sorted = sorted(under)

                    # If there are elements in both lists then just return the correct order of ACKs dealing with overflow and reordering
                    if (over_sorted and under_sorted):

                        # Deal with overflow and reordering of received segments
                        # Only for the case when both under and over lists have elements
                        # e.g. when buffer_seq = [24,25,30,0,27]
                        # After separation: over_sorted = [24,25,27,30] and under_sorted = [0]
                        # But desired result is sorted_buffer_seq = [24,25,27,30,0] so pure sorting will not yield the desired result
                        # The following function produces the result
                        log.debug(self.win)
                        if (over_sorted[0] >= max_value-(self.win) and under_sorted[0] <= (self.win)):
                            sorted_buffer_seq = over_sorted + under_sorted
                        else:
                            sorted_buffer_seq = under_sorted + over_sorted

                    # Else if only one list has elements return the sorted corresponding list
                    elif (over_sorted and not under_sorted):
                        sorted_buffer_seq = over_sorted
                    elif (under_sorted and not over_sorted):
                        sorted_buffer_seq = under_sorted
                    # If there are no elements in the buffer_seq list, return an empty list
                    elif (not under_sorted and not over_sorted):
                        sorted_buffer_seq = []


                    # Find sequence numbers that are not consecutive with their neighbour sequence number in the sequence number list
                    # "ranges" list includes the starting and ending points of different blocks in the sequence number list
                    # Does not consider it a separate range if from (2**self.n_bits-1) we go to 0 (same range) - Deals with sequence number overflow
                    log.debug(self.buffer_seq)
                    log.debug(sorted_buffer_seq)
                    ranges = sum((list(seq_num) for seq_num in zip(sorted_buffer_seq, sorted_buffer_seq[1:]) if (seq_num[0]+1 != seq_num[1] and seq_num[0] != (2**self.n_bits-1))), [])

                    # "iranges" is an iterator giving the starting and ending points of different blocks including the first and final blocks
                    iranges = iter(sorted_buffer_seq[0:1] + ranges + sorted_buffer_seq[-1:])

                    # Create a list that saves starting and ending points
                    start_end_ranges = []
                    for x in iranges:
                        start_end_ranges.append(x)

                    # 1 Block
                    if (len(start_end_ranges) == 2):

                      header_length = 9
                      block_length = 1
                      first_1 = start_end_ranges[0]
                      len_1 = start_end_ranges[1] - first_1 + 1

                    # 2 Blocks
                    elif (len(start_end_ranges) == 4):

                      header_length = 12
                      block_length = 2
                      first_1 = start_end_ranges[0]
                      len_1 = start_end_ranges[1] - first_1 + 1

                      first_2 = start_end_ranges[2]
                      len_2 = start_end_ranges[3] - first_2 + 1

                    # 3 Blocks
                    elif (len(start_end_ranges) >= 6):

                      header_length = 15
                      block_length = 3
                      first_1 = start_end_ranges[0]
                      len_1 = start_end_ranges[1] - first_1 + 1

                      first_2 = start_end_ranges[2]
                      len_2 = start_end_ranges[3] - first_2 + 1

                      first_3 = start_end_ranges[4]
                      len_3 = start_end_ranges[5] - first_3 + 1

                    # Deal with sequence number overflow
                    # In this case the length of the range is negative so to get the right length of the range
                    # We need to calculate 32 + len (len is negative so essentially subtraction)
                    # E.g. for self.n_bits = 5 and buffer_seq = [30,31,0,1,2]
                    # len of the range with above calculations is -27 so it becomes 32 + (-27) = 5 (correct length)
                    if (len_1<0):
                      len_1 = 2**self.n_bits + len_1
                    if (len_2<0):
                      len_2 = 2**self.n_bits + len_2
                    if (len_3<0):
                      len_3 = 2**self.n_bits + len_3


                    # SACK Segment
                    header_GBN = GBN(type="ack",
                                     options=1,
                                     len=0,
                                     hlen=header_length,
                                     num=self.next,
                                     win=self.win,
                                     blen=block_length,
                                     left_1=first_1,
                                     length_1=len_1,
                                     padd_2=0,
                                     left_2=first_2,
                                     length_2=len_2,
                                     padd_3=0,
                                     left_3=first_3,
                                     length_3=len_3
                                     )

                    log.debug("Sending (S)ACK: %s, [Block_length: %s, Left 1: %s, Length 1: %s, Left 2: %s, Length 2: %s, Left 3: %s, Length 3: %s]", self.next,block_length,first_1,len_1,first_2,len_2,first_3,len_3)
                    send(IP(src=self.receiver, dst=self.sender) / header_GBN,
                         verbose=0)




                # last packet received and all ACKs successfully transmitted
                # --> close receiver
                #print("end_receiver: ", self.end_receiver," end_num: ",  self.end_num, " next: ", self.next)
                if self.end_receiver and self.end_num == self.next:
                    raise self.END()

            # transition to WAIT_SEGMENT to receive next segment
            raise self.WAIT_SEGMENT()


if __name__ == "__main__":
    # get input arguments
    parser = argparse.ArgumentParser('GBN receiver')
    parser.add_argument('receiver_IP', type=str,
                        help='The IP address of the receiver')
    parser.add_argument('sender_IP', type=str,
                        help='The IP address of the sender')
    parser.add_argument('n_bits', type=int,
                        help='The number of bits used to encode the sequence '
                        'number field')
    parser.add_argument('output_file', type=str,
                        help='Path to the output file (data from sender is '
                        'stored in this file)')
    parser.add_argument('window_size', type=int,
                        help='The window size of the receiver')
    parser.add_argument('data_l', type=float,
                        help='The loss probability of a data segment '
                        '(between 0 and 1.0)')
    parser.add_argument('ack_l', type=float,
                        help='The loss probability of an ACK '
                        '(between 0 and 1.0)')
    parser.add_argument('--interface', type=str, help='(optional) '
                        'interface to listen on')

    args = parser.parse_args()

    if args.interface:
        conf.iface = args.interface

    output_file = args.output_file    # filename of output file
    size = 2**6                       # normal payload size
    bits = args.n_bits
    assert bits <= 8

    # delete previous output file (if it exists)
    if os.path.exists(output_file):
        os.remove(output_file)


    # initial setup of automaton
    GBN_receiver = GBNReceiver(args.receiver_IP, args.sender_IP, bits,
                               output_file, args.window_size, args.data_l,
                               args.ack_l, size)
    # start automaton
    GBN_receiver.run()

