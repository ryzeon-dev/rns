main:
	mkdir -p ./bin
	cargo build -r 
	mv ./target/release/rns ./bin/rns
	rm -rf ./target

install:
	cp ./bin/rns /usr/local/bin