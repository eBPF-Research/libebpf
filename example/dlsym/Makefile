dlsym:
	# gcc main.c -rdynamic -o dlsym 
	gcc main.c -Wl,-export-dynamic -o dlsym 
.PHONY: clean
clean:
	rm dlsym
