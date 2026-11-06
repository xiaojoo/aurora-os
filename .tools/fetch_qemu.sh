set -u
cd /h/aurora-os/.tools
URL=https://qemu.weilnetz.de/w64/2026/qemu-w64-setup-20260811.exe
TOTAL=206615928
CHUNKS=10
rm -f part.* qemu-merged.exe
for i in $(seq 0 $((CHUNKS-1))); do
  S=$(( i * TOTAL / CHUNKS ))
  E=$(( (i+1) * TOTAL / CHUNKS - 1 ))
  [ $i -eq $((CHUNKS-1)) ] && E=$((TOTAL-1))
  curl -s --max-time 1200 -r ${S}-${E} -o part.$i "$URL" &
done
wait
cat part.* > qemu-merged.exe
echo "merged=$(stat -c %s qemu-merged.exe) expect=$TOTAL"
for i in $(seq 0 $((CHUNKS-1))); do echo "part.$i=$(stat -c %s part.$i)"; done
