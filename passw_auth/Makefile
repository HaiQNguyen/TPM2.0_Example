tcci_helper=../tcti_helper/*c
lib_dir=/usr/local/lib

test: passw_auth.c $(tcci_helper)
	gcc passw_auth.c $(tcci_helper) -Wall -L=$(lib_dir) -ltss2-esys -ltss2-mu -ltss2-rc \
	-ltss2-sys -ltss2-tctildr -ltss2-tcti-mssim -ltss2-tcti-tabrmd -o passw_auth

.PHONY: clean
clean:
	rm passw_auth
