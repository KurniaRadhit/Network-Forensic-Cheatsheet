find . -type f -exec sha256sum {} \; | sort
find . -type f -exec sha256sum {} \; | sort | uniq -w64 -u
