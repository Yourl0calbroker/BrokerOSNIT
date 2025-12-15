Usage:
This is an in depth OSNIT tool designed for Instagram

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
Important Note:

If an error is encountered with 2FA, either turn off 2FA temporarily or create a new account for use

Any errors regarding logging in for Session ID retrieval can be a result of account suspension if an account automated requests become obvious

Session ID related issues are temporary and so are activity suspensions regarding the requests for API information

If Session ID issues persists, log into the Instagram account and check for notifications regarding unusual activity and verify it was you
