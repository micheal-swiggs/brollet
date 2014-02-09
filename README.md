Brollet
==

**Try it out** here [https://brollet.org](https://brollet.org) and join the [discussion](https://bitcointalk.org/index.php?topic=454000.0).

A secure, deterministic, online and offline browser wallet.

* Brollet can be run on your local PC or Mac, but does not require downloading the blockchain to send or receive bitcoins.

* Brollet can be hosted on a VPS so you can access it from anywhere with any browser or mobile device.

* Brollet is a deterministic brain wallet. Your passphrase is used to generate all your bitcoin addresses. To backup your wallet, just backup your passphrase. No wallet file is used so there is no change of the wallet file being lost or stolen.

* Brollet support the Electurm and Armory wallets formats as well as importing keys from a wallet file.

* Brollet supports sending bitcoins to anyone with an email address. They will receive an email with instructions on how to redeem the bitcoins that have been sent. No centeral server or 3rd party is used in the process. If the recipient does not redeem the bitcoins the sender can recover them again.

* Brollet source code is freely available and completely under your control. No dependancy on a 3rd party to host your online wallet.



#Installation

###On Unix or Mac

Make sure your system has Python installed.
```
./brollet start
```
Open a web browser to http://localhost:9696 or http://yourDomain:9696

to stop it run:
```
./brollet stop
```



###On Windows

Make sure your system has Python installed.

Open a command prompt window
```
cd brollet
```

Edit the httpd.bat file to set the path to your python.exe
httpd.bat

Open a web browser to http://localhost:9696 

#Settings
To change the settings from the Settings page you need to first edit the file
   web/cgi-bin/config.json
and set the "password" field.

# Tutorials

Checkout the docs the directory!

* [My First Multisig Transaction](/docs/)

* * *

**Donations are welcome:** 3Q1kpuG9ewSa1Sj7gK9NSJGdrsf2LEL7Sx (multisignature address!)
