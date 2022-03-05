for /L %%i IN (12025,50,30000) DO (
	tshark -r EchoDot.pcap -T fields -E separator=, -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e frame.time_delta_displayed -e ip.len ip.addr==192.168.1.50 |head -%%i | tail -50 > EchoDot.csv
	python CalcEcho.py
	)

python join.py

for /L %%i IN (50,50,18000) DO (
	tshark -r Torii.pcap -T fields -E separator=, -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e frame.time_delta_displayed -e ip.len ip.addr==192.168.100.103 |head -%%i | tail -50 > DoorLock.csv
	python CalcLock.py
	)

python join.py

for /L %%i IN (25,50,18000) DO (
	tshark -r Light.pcap -T fields -E separator=, -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e frame.time_delta_displayed -e ip.len ip.addr==192.168.1.132 |head -%%i | tail -50 > Light.csv
	python CalcLight.py
	)

python join.py

for /L %%i IN (25,50,18000) DO (
	tshark -r FYPATK.pcap -T fields -E separator=, -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e frame.time_delta_displayed -e ip.len ip.addr==192.168.1.195 |head -%%i | tail -50 > FYPATK.csv
	tshark -r FYPNOM.pcap -T fields -E separator=, -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e frame.time_delta_displayed -e ip.len ip.addr==192.168.1.132 |head -%%i | tail -50 > FYPNOM.csv
	python Calc.py
	)

python join.py


