#!/bin/bash
################################################################################
# Changeable parameters                                                        #
################################################################################

# Parameters for global test
NEIGHBOR=X                   # The group to communicate with. [X = group number]
TEST_SENDER_OR_RECEIVER=1    # 1 for sender, 2 for receiver

# Parameters for sender and receiver
NBITS=5                      # Number of bits used to encode the sequence number

# Parameters for sender
SENDER_FILE="sender.py"      # Sender file to use
IN_FILE=sample_text.txt      # Data to send [e.g. sample_text.txt or ETH_logo.png]
SENDER_WIN_SIZE=4            # Window size of the sender
Q_4_2=0                      # Use Selective Repeat (Q4.2) [0 or 1]
Q_4_3=0                      # Use Selective Acknowledgments (Q4.3) [0 or 1]
Q_4_4=0                      # Use Congestion Control (Q4.4/Bonus) [0 or 1]

# Parameters for receiver
RECEIVER_FILE="receiver.py"  # Receiver file to use
OUT_FILE=out_temp.txt        # Output file for the received data from the sender
RECEIVER_WIN_SIZE=4          # Window size of the receiver
DATA_L=0                     # Loss probability for data [between 0 and 1.0]
ACK_L=0                      # Loss probability for ACKs [between 0 and 1.0]

################################################################################
# END changeable parameters                                                    #
################################################################################

# Python executable to use
PYTHON="python3"

# Your IP addresses (sender or receiver). Do not change!
MY_IP="192.168.56.86"
NEIGHBOR_IP="192.168.56.$NEIGHBOR"

function sender {
        echo "$PYTHON $SENDER_FILE $MY_IP $NEIGHBOR_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_4_2 $Q_4_3 $Q_4_4 --interface=enp0s8"
}

function receiver {
        echo "$PYTHON $RECEIVER_FILE $MY_IP $NEIGHBOR_IP $NBITS $OUT_FILE $RECEIVER_WIN_SIZE $DATA_L $ACK_L --interface=enp0s8"
}


# To terminate the sender and receiver if e.g. ctrl-c is used
function clean_up {
        echo "clean_up"
        if [ $TEST_SENDER_OR_RECEIVER -eq 1 ]; then
                ps ax | grep "$(sender)" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done
        fi

        if [ $TEST_SENDER_OR_RECEIVER -eq 2 ]; then
                ps ax | grep "$(receiver)" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done
        fi

        exit
}

trap clean_up INT TERM

# Check that Selective Repeat and SACK are not used at the same time
if [ $Q_4_2 -eq 1 -a $Q_4_3 -eq 1 ]; then
        echo "You cannot use Selective Repeat and SACK at the same time."
        exit 1
fi

# Start sender if TEST_SENDER_OR_RECEIVER==1
if [ $TEST_SENDER_OR_RECEIVER -eq 1 ]; then
        echo "Start sender"
        sudo $(sender) &
fi

# Start receiver if TEST_SENDER_OR_RECEIVER==2
if [ $TEST_SENDER_OR_RECEIVER -eq 2 ]; then
        echo "Start receiver"
        sudo $(receiver) &
fi

wait
     

