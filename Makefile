.PHONY: all docs clean

all:
	@echo "Run \`make docs\` or \`make clean\`."

docs:
	$(MAKE) -C docs/

clean:
	$(MAKE) -C docs/ clean

