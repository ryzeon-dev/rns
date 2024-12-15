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

compile-gui:
	cd ./gui && bash compile.sh

install-gui:
	cp ./gui/bin/rns-gui /usr/local/bin/rns-gui

install-gui-amd64:
	cp ./gui/bin/linux_amd64/rns-gui /usr/local/bin/rns-gui

install-gui-arm64:
	cp ./gui/bin/linux_arm64/rns-gui /usr/local/bin/rns-gui