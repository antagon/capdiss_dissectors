.PHONY: all doc clean

all:
	$(MAKE) -C src/

doc:
	$(MAKE) -C doc/ doc

clean:
	$(MAKE) -C src/ clean
	$(MAKE) -C doc/ clean

