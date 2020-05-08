all:
	gcc -Iinclude main.c -Llib -lkirk -o decrypt_sp
	
clean:
	rm decrypt_sp