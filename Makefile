MAKE_PKG = ./utils/make_pkg.sh
MAKE_MD5SUMS = ./utils/make_md5sums.sh


.PHONY: all clean md5sums sign coroner docs

all: coroner md5sums docs

coroner:
	$(MAKE_PKG) ./src

md5sums:
	$(MAKE_MD5SUMS) ./

docs:
	$(MAKE) -C docs/

sign:
	@gpg2 --detach-sign -u 484D301C MD5SUMS

clean:
	$(MAKE) -C docs/ clean
	rm -f *.tar.gz
	rm -f *.rockspec
	rm -f *.rock
	rm -f *.sig
	rm -f MD5SUMS

