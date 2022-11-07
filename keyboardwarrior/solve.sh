tshark -r ./keyboardwarrior.pcap -Y 'btatt.opcode == 0x1b && btatt.handle == 0x001d && btatt.value != 00:00:00:00:00:00:00:00' -T fields -e btatt.value | sed 's/\(..\)/\1:/g' > blue.txt
