sudo rm /boot/vmlinuz-6.4.0-wasp*
sudo rm /boot/initrd.img-6.4.0-wasp*
git pull
git log -1 --pretty=format:"%h %s (%ci)"
make -j$(nproc)
sudo make modules_install
sudo make install
