#!/bin/bash
################################################################################
# Changeable parameters                                                        #
################################################################################

# Filenames of receiver and sender implementation
RECEIVER_FILE="receiver.py"
SENDER_FILE="sender.py"

# Parameters for sender and receiver
NBITS=5                   # Number of bits used to encode the sequence number

# Parameters for sender
IN_FILE=sample_text.txt   # Data to send [e.g. sample_text.txt or ETH_logo.png]
SENDER_WIN_SIZE=4         # Window size of the sender
Q_4_2=1                   # Use Selective Repeat (Q4.2) [0 or 1]
Q_4_3=0                   # Use Selective Acknowledgments (Q4.3) [0 or 1]
Q_4_4=0                   # Use Congestion Control (Q4.4/Bonus) [0 or 1]

# Parameters for receiver
OUT_FILE=out_temp.txt     # Output file for the received data from the sender
RECEIVER_WIN_SIZE=4       # Window size of the receiver
DATA_L=0.2                  # Loss probability for data [between 0 and 1.0]
ACK_L=0.2                   # Loss probability for ACKs [between 0 and 1.0]

################################################################################
# END changeable parameters                                                    #
################################################################################

# Python executable to use
PYTHON="python3"

# Your local IP addresses. Do not change!
LOCAL_SENDER_IP="1.0.0.1"
LOCAL_RECEIVER_IP="1.0.0.2"

function sender {
        echo "$PYTHON $SENDER_FILE $LOCAL_SENDER_IP $LOCAL_RECEIVER_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_4_2 $Q_4_3 $Q_4_4"
}

function receiver {
        echo "$PYTHON $RECEIVER_FILE $LOCAL_RECEIVER_IP $LOCAL_SENDER_IP $NBITS $OUT_FILE $RECEIVER_WIN_SIZE $DATA_L $ACK_L"
}


# To terminate the sender and receiver if e.g. ctrl-c is used
function clean_up {
        echo "clean_up"

        ps ax | grep "$(sender)" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done

        ps ax | grep "$(receiver)" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done

        exit
}

trap clean_up INT TERM

# Check that Selective Repeat and SACK are not used at the same time
if [ $Q_4_2 -eq 1 -a $Q_4_3 -eq 1 ]; then
        echo "You cannot use Selective Repeat and SACK at the same time."
        exit 1
fi

# Start the receiver
echo "Start receiver"
sudo ip netns exec receiver_ns $(receiver) &

sleep 0.5

# Start the sender
echo "Start sender"
sudo ip netns exec sender_ns $(sender) &

wait



