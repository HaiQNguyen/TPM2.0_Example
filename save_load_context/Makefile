tcci_helper=../tcti_helper/*c
lib_dir=/usr/local/lib

test: save_load_context.c $(tcci_helper)
	gcc save_load_context.c $(tcci_helper) -Wall -L=$(lib_dir) -ltss2-esys -ltss2-mu -ltss2-rc \
	-ltss2-sys -ltss2-tctildr -ltss2-tcti-mssim -ltss2-tcti-tabrmd -o save_load_context

.PHONY: clean
clean:
	rm save_load_context
