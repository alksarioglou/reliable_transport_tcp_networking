#!/bin/bash
########################################################################################################
# Changeable parameters                                                                                #
########################################################################################################

# The test you want to perform
# 1: sender Q4.1 (header, ACK handling and retransmission after timeout)
# 2: receiver Q4.2 (buffering of out-of-order packets)
# 3: sender Q4.2 (Selective Repeat)
# 4: receiver Q4.3 (SACK header generation)
# 5: sender Q4.3 (retransmission after receiving SACK header)
TEST_NUM=1

# Filenames of receiver and sender implementation
RECEIVER_FILE="receiver.py"
SENDER_FILE="sender.py"

########################################################################################################
# END changeable parameters                                                                            #
########################################################################################################

# Your IP address (sender or receiver). Do not change!
MY_IP="192.168.56.86"

# The port used for the external TCP connection to the test server.
PORT=10086

NEIGHBOR_IP="192.168.56.99"

# Start client
sudo python3 client.py $NEIGHBOR_IP $PORT $TEST_NUM &

# Parameters for sender and receiver
NBITS=5

# Parameters for sender
IN_FILE=to_send_test.txt

# Parameters for receiver
OUT_FILE=out_test.txt
DATA_L=0
ACK_L=0

# To terminate the sender and receiver if e.g. ctrl-c is used
function clean_up {
        echo "clean_up"

        ps ax | grep "python3 client.py $NEIGHBOR_IP $PORT $TEST_NUM" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done

        if [ $TEST_NUM -eq 1 ] || [ $TEST_NUM -eq 3 ] || [ $TEST_NUM -eq 5 ]; then
                ps ax | grep "python3 $SENDER_FILE $MY_IP $NEIGHBOR_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_4_2 $Q_4_3 $Q_4_4 --interface=enp0s8" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done
        fi

        if [ $TEST_NUM -eq 2 ] || [ $TEST_NUM -eq 4 ]; then
                ps ax | grep "python3 $RECEIVER_FILE $MY_IP $NEIGHBOR_IP $NBITS $OUT_FILE $RECEIVER_WIN_SIZE $DATA_L $ACK_L --interface=enp0s8" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done
        fi

        exit
}

trap clean_up INT TERM

if [ $TEST_NUM -eq 1 ]; then
        echo "Start sender for test 1"
        sleep 2
        SENDER_WIN_SIZE=5
        Q_4_2=0
        Q_4_3=0
        Q_4_4=0
        sudo python3 $SENDER_FILE $MY_IP $NEIGHBOR_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_4_2 $Q_4_3 $Q_4_4 --interface=enp0s8 &
fi

if [ $TEST_NUM -eq 2 ]; then
        echo "Start receiver for test 2"
        RECEIVER_WIN_SIZE=5
        sudo python3 $RECEIVER_FILE $MY_IP $NEIGHBOR_IP $NBITS $OUT_FILE $RECEIVER_WIN_SIZE $DATA_L $ACK_L --interface=enp0s8 &
fi

if [ $TEST_NUM -eq 3 ]; then
        echo "Start sender for test 3"
        sleep 2
        SENDER_WIN_SIZE=4
        Q_4_2=1
        Q_4_3=0
        Q_4_4=0
        sudo python3 $SENDER_FILE $MY_IP $NEIGHBOR_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_4_2 $Q_4_3 $Q_4_4 --interface=enp0s8 &
fi

if [ $TEST_NUM -eq 4 ]; then
        echo "Start receiver for test 4"
        RECEIVER_WIN_SIZE=10
        sudo python3 $RECEIVER_FILE $MY_IP $NEIGHBOR_IP $NBITS $OUT_FILE $RECEIVER_WIN_SIZE $DATA_L $ACK_L --interface=enp0s8 &
fi

if [ $TEST_NUM -eq 5 ]; then
        echo "Start sender for test 5"
        sleep 2
        SENDER_WIN_SIZE=10
        Q_4_2=0
        Q_4_3=1
        Q_4_4=0
        sudo python3 $SENDER_FILE $MY_IP $NEIGHBOR_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_4_2 $Q_4_3 $Q_4_4 --interface=enp0s8 &
fi

wait

