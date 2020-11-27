#!/bin/bash

# String searched in serial output indicating the end of program
eof_marker="# lwc exit"
#eof_marker="Count = 72"

outfile=$1
PID=0
function wait_eof_marker() {
    echo "wait_eof_marker $outfile"
	# Check output file periodically until the end of file marker is found or an exception is generated
    count=0
	while [ $count -eq 0 ]
	do
		sleep 3s
		count=$(grep -c "$eof_marker" $outfile)

		# nodemcuv2 can generate exceptions
		except=$(grep -c "CUT HERE FOR EXCEPTION DECODER" $outfile)

		count=$(($count + $except))

        if [[ $PID -eq 0 ]]; then
            PIDSET=`pgrep -f "platformio device monitor"`
            if [[ $PIDSET -ne 0 ]]; then
                PID=$PIDSET
                echo "Found process PID=$PID"
            else
                echo "Process not found yet"
            fi
        else
            if [ -n "$PID" -a -e /proc/$PID ]; then
                tvcount=$(grep -c "Count" $outfile)
                printf "\r process running, test vectors done so far: $tvcount"
            else
                printf "\n"
                echo "process does not exists anymore"
                exit 1
            fi
        fi

	done
    printf "\n"
    echo "wait_eof_marker exit"
    if [ -n "$PID" -a -e /proc/$PID ]; then
        echo "Killing process $PID"
        kill -9 $PID
    fi
}

wait_eof_marker
