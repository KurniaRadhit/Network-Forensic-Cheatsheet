find . -type f -exec sha256sum {} \; | sort

find . -type f -exec sha256sum {} \; | sort | uniq -w64 -u

find . -type f -exec sha256sum {} \; | sort > hashes.txt

awk '{print $1}' hashes.txt | sort | uniq -c
