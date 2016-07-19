.PHONY: all docs clean

all:
	$(MAKE) -C src/

docs:
	$(MAKE) -C docs/

clean:
	$(MAKE) -C src/ clean
	$(MAKE) -C docs/ clean

