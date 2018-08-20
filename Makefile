MODULES!=ls -d */

all:
	for mod in $(MODULES); do \
		make -C $${mod}; \
	done
