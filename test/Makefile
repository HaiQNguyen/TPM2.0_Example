tcci_helper=../ttci_helper/*c

test: test.c $(tcci_helper)
	gcc test.c $(tcci_helper)-Wall -L=/usr/local/lib -ltss2-esys -ltss2-mu -ltss2-rc \
	-ltss2-sys -ltss2-tctildr -ltss2-tcti-mssim -ltss2-tcti-tabrmd -o test

.PHONY: clean
clean:
	rm test
