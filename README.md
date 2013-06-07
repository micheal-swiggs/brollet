ew
==

EZWallet

The biggest problem faced by anyone wanting to get started with bitcoin is how to store the priviate keys linked to the public bitcoin addresses. 

The most common approach is to store the keys in a file and encrypt the file. But this has the problem that if the file is lost due to a disk failure, disaster or stolen computer the bitcoins are lost.

Another approach is to use a web service that manages your wallet for you. This requires you to depend on the web service always being available. Also you have to trust that the service provider will remain honest and not vanish with everyones bitcoins. If the web service shuts down then your bitcoins are lost.

The safest approch is to use a deterministic wallet so that private keys can be generated from a seed and do not need to be stored. The source code for this wallet should be viewable/readable and under your control. Ideally the wallet code should be able to run completely within a web browser using only HTML5 and JavaScript without any dependencies on plugins or code that is not viewable. It would be even nicer if the same code base worked in FireFox, Chrome and Opera and could be used on Window, Mac, Linux, iPhone and Android.

The goal of this project is to build such a wallet. A wallet that is easy to use and provides safe storage.

You can try it out here: http://arimaa.com:9696

