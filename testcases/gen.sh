echo "EASY PACKET FUZZ RULE CONFIG SCRIPT BUZZWORD LOL.JPG"
#python3 parse.py
echo "Setting up directories..."
mkdir ./dump
mkdir ./radamsa
echo "Generating input testcases from PCAP that match rule..."
python3 generateTestcases.py
echo "Fuzzing Test cases..."
radamsa -r -n 10000 -o ./radamsa/fuzz-%n ./dump/*
echo "Filtering and organizing testcases into object..."
python3 exportTestcases.py
echo "Cleaning up..."
rm -r ./dump
rm -r ./radamsa
echo "DONE."
