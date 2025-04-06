# lfi_rfi
    LFI scan only:

python3 scanner.py -u "http://testphp.vulnweb.com/listproducts.php?cat=" --lfi

    RFI scan only:

python3 scanner.py -u "http://example.com/vuln.php?page=" --rfi

    Both LFI & RFI:

python3 scanner.py -u "http://target.com/vuln.php?page=" --lfi --rfi
