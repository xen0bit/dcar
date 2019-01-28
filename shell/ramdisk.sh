echo "Making directory for RAM Disk"
sudo mkdir /mnt/pktramdisk
echo "Mounting /mnt/pktramdisk"
sudo mount -t tmpfs -o rw,size=256M tmpfs /mnt/pktramdisk
