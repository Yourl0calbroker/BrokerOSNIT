Installation:
```
pkg install git python -y && pip install requests stdiomask && git clone https://github.com/Yourl0calbroker/BrokerOSNIT.git $HOME/BrokerOSNIT && chmod +x $HOME/BrokerOSNIT/BrokerOSNIT.py && mkdir -p $HOME/bin && if ! grep -q 'export PATH="$HOME/bin:$PATH"' $HOME/.bashrc; then echo 'export PATH="$HOME/bin:$PATH"' >> $HOME/.bashrc; fi && source $HOME/.bashrc && ln -sf $HOME/BrokerOSNIT/BrokerOSNIT.py $HOME/bin/BrokerOSNIT.py && echo "Installation complete. Run the script by typing: BrokerOSNIT.py"
```

Run with command 
```
BrokerOSNIT.py
```

Updating: 
```
cd BrokerOSNIT && git pull origin main
```
