echo "Setting IPTables rules for packet capture..."
#OSRS
#C-->S Port 54258
#sudo iptables -t raw -A PREROUTING -p tcp --source-port 54258 -j NFQUEUE --queue-num 1
#S-->C Port 43594
sudo iptables -t raw -A PREROUTING -p tcp --source-port 80 -j NFQUEUE --queue-num 1
#iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
#sudo iptables -t raw -A PREROUTING -p tcp --source-port 1000:55000 -j NFQUEUE --queue-num 1
#sudo iptables -t raw -A PREROUTING -p tcp --source-port 80 -j NFQUEUE --queue-num 1
#sudo iptables -t raw -A PREROUTING -p tcp --destination-port 43595 -j NFQUEUE --queue-num 1

