proxy_cache: proxy_cache.c
	gcc -pthread $@ $^ -lcrypto