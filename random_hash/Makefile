tcci_helper=../ttci_helper/*c
lib_dir=/usr/local/lib

test: random_hash.c $(tcci_helper)
	gcc random_hash.c $(tcci_helper) -Wall -L=$(lib_dir) -ltss2-esys -ltss2-mu -ltss2-rc \
	-ltss2-sys -ltss2-tctildr -ltss2-tcti-mssim -ltss2-tcti-tabrmd -o random_hash

.PHONY: clean
clean:
	rm test
