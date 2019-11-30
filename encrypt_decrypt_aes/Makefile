tcci_helper=../tcti_helper/*c
lib_dir=/usr/local/lib

test: encrypt_decrypt_aes.c $(tcci_helper)
	gcc encrypt_decrypt_aes.c $(tcci_helper) -Wall -L=$(lib_dir) -ltss2-esys -ltss2-mu -ltss2-rc \
	-ltss2-sys -ltss2-tctildr -ltss2-tcti-mssim -ltss2-tcti-tabrmd -o encrypt_decrypt_aes

.PHONY: clean
clean:
	rm encrypt_decrypt_aes
