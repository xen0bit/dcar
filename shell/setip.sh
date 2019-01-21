echo "Setting IPTables rules for packet capture..."
#Client Port 54258-->Server
#sudo iptables -t raw -A PREROUTING -p tcp --source-port 54258 -j NFQUEUE --queue-num 1
#Server Port 80-->Client
sudo iptables -t raw -A PREROUTING -p tcp --source-port 80 -j NFQUEUE --queue-num 1

