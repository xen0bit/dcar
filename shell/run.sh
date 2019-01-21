#echo "Running docker container..."
#sudo docker run -it --rm                 --cap-add=NET_ADMIN                 --#net=host                 --name=nfqueuelistener nfqueuelistener
echo "Running nfqueue listener..."
cd python
python3 nfqueue_listener3_radamsa.py
