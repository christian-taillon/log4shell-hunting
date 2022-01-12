echo "decode base64.txt and extract ioc"
base64 -d /tmp/base64_dump.txt  | iocextract --output /tmp/base64_dump_decoded.txt
echo "find unique IPs and number of occurances"
sort -u /tmp/base64_dump_decoded.txt
rm /tmp/base64_dump_decoded.txt
