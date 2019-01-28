#Weird stuff happens if tz isnt right
sudo apt-get update && apt-get install -y tzdata
#Various tools
sudo apt-get update && apt-get install -y zip unzip python3 python3-pip python-pyx python-matplotlib tcpdump python-crypto graphviz imagemagick gnuplot python-gnuplot libpcap-dev && apt-get clean
#More stuff pulled from docker build script, some duplicates, but no harm done
sudo apt-get update && apt-get install -y bridge-utils net-tools iptables python3 tcpdump build-essential python3-dev libnetfilter-queue-dev python3-pip
#Scapy
pip3 install scapy
#NetfilterQueue
pip3 install NetfilterQueue
#Install Colorama for pretty diff
pip3 install colorama
#Install stuff for radamsa
sudo apt-get update && apt-get install -y gcc make git wget
git clone https://gitlab.com/akihe/radamsa.git
cd radamsa
make && sudo make install
echo "SETUP COMPLETE"
