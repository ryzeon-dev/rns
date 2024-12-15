python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install pyinstaller

pyinstaller --onefile ./src/main.py --name rns-gui --windowed
cp ./dist/rns-gui ./bin/rns-gui

deactivate
rm -rf ./dist ./build ./venv ./rns-gui.spec