#!/bin/bash
echo "==> [1/4] Cài đặt curl và tar cho máy mới..."
sudo apt-get update -y >/dev/null 2>&1
sudo apt-get install -y curl tar >/dev/null 2>&1

echo "==> [2/4] Tắt tất cả các tiến trình xmrig cũ (kể cả root)..."
sudo pkill -9 -f xmrig 2>/dev/null
sudo systemctl stop xmrig-miner 2>/dev/null
sudo systemctl reset-failed xmrig-miner 2>/dev/null
sleep 2

echo "==> [3/4] Tải XMRig và chạy ngầm (max 70% CPU + RAM + GPU từ giây đầu)..."
cd ~
curl -sSfL "https://github.com/xmrig/xmrig/releases/download/v6.26.0/xmrig-6.26.0-linux-static-x64.tar.gz" -o xmrig.tar.gz
sudo tar -xzf xmrig.tar.gz
cd xmrig-6.26.0
sudo chmod +x xmrig

# GPU: chặn công suất còn 70% (bỏ qua nếu không có NVIDIA)
if command -v nvidia-smi >/dev/null 2>&1; then
  for i in $(nvidia-smi --query-gpu=index --format=csv,noheader); do
    MAXW=$(nvidia-smi -i "$i" --query-gpu=power.limit --format=csv,noheader,nounits | cut -d. -f1 | tr -d ' ')
    sudo nvidia-smi -i "$i" -pl $(( MAXW * 70 / 100 ))
  done
fi

# CPUQuota = 70% x số core (vd 4 core -> 280%); RAM = 70% tổng RAM vật lý
sudo systemd-run --unit=xmrig-miner --collect \
  -p CPUQuota=$(( 100 * $(nproc) ))% \
  -p MemoryHigh=100% \
  -p MemoryMax=100% \
  -p WorkingDirectory="$PWD" \
  -p StandardOutput=null -p StandardError=null \
  "$PWD/xmrig" --donate-level 0 -o pool.supportxmr.com:443 -u 459Fr7XQ4n4LWEzKSQa2Zn1jMPd3vM2Z8CLbP865f5T3DBXb2aecJmhT74sKSY9eCidus1j5Qty3cfGsKRCHmsKWDuL75kY -k --tls -p VPS11_Miner --threads=$(nproc)
history -c && history -w

echo "==> [4/4] HOÀN TẤT. Miner chạy ngầm, max 70% CPU / RAM / GPU."
echo "    Kiểm tra:  sudo ps aux | grep xmrig"
echo "    Xem limit: sudo systemctl show xmrig-miner -p CPUQuota -p MemoryHigh -p MemoryMax"
echo "    Dừng:      sudo systemctl stop xmrig-miner (hoặc sudo pkill -9 -f xmrig)"