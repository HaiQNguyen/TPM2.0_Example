sudo tpm2-abrmd --allow-root --tcti=mssim &
tpm2_clear
tpm2_clearcontrol
pid=$(pgrep tpm2-abrmd)
echo "pid: $pid"
sudo kill $pid
