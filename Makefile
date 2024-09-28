main:
	mkdir -p ./bin
	cargo build -r 
	mv ./target/release/rns ./bin/rns
	rm -rf ./target

install:
	cp ./bin/rns /usr/local/bin

install-amd64:
	cp ./bin/linux_amd64/rns /usr/local/bin

install-arm64:
	cp ./bin/linux_arm64/rns /usr/local/bin
