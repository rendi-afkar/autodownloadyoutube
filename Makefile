CC ?= cc

all: deps main

deps:
	@python -c "import cryptography" 2>/dev/null || pip install cryptography
	@command -v yt-dlp >/dev/null 2>&1 || pip install -U yt-dlp
	@command -v ffmpeg >/dev/null 2>&1 || echo "[!] ffmpeg belum ada. Install: pkg install ffmpeg"

main: main.c
	$(CC) -O2 -o main main.c

clean:
	rm -f main

.PHONY: all deps clean
