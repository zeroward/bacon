#!/usr/bin/env bash

ssid_list=$(tshark -2 -R "wlan.fc.type==0 && wlan.fc.subtype==8" -r mgmt_beacons.pcap | awk '{print $3}' | sort -u)
for ssid in $ssid_list; do
  tmpfile=$(mktemp)
  tag_list=$(tshark -2 -R "wlan.fc.type==0 && wlan.fc.subtype==8 && wlan.addr_resolved==$ssid" -c 1 -r mgmt_beacons.pcap -T json | grep -o '"wlan.tag.number": ".*"' | grep -o '[0-9]*'  > $tmpfile)
  sed -i 's/\s/\n/g' $tmpfile
  match=3
  match_list=""
  echo $ssid
  echo "best guess firmware"
  for file in $(ls files); do
    diff=$(diff $tmpfile files/$file | grep '^>' | wc -l)
    if [ $diff -lt $match ]; then
      if [[ "$match_list" -eq "" ]]; then
        match=$diff
        match_list="$file"
      else
        match_list=("$match_list $match \n $file $diff")
        match=$diff
      fi
    fi
  done;
  echo $match_list
  echo ""
done;
