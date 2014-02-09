
# My First Multisig Transaction

This tutorial is about how to use Brollet to create a `3-out-of-3` transaction.

Creating a multisignature address in 3 steps:

1. Collecting the public keys.
1. Creating the redeem-script & multisignature address. Saving the redeem-script for spending bitcoins.
1. Sending bitcoins to the multisignature address.

Spending bitcoins from the multisignature address requires 3 steps:

1. Using the redeem-script to create a transaction.
1. Signing the transaction with the required number of signatures.
1. Broadcasting the transaction!


# Creating multisig address

_First_ sign into brollet using your email and super strong password. This will bring you to the **home page**.

![home page](/docs/images/balance.png)

_Next_ click on the `Public Keys` button and since we will be doing a 3 out-of 3 transaction copy the first 3 public keys.

![pubkey page](/docs/images/pubkeys.jpg)

_You_ will then click on the `New Redeemscript` button found on the home page. Then enter the 3 public keys and for `No. Signatures` enter 3. You will now be able to see the Multisignature address and the redeem-script. Make a copy (and save it) of the redeem-script and multisignature address. You also have the option of sending bitcoins from Brollet.

> Notice that `Your Brollet Public Key` is automatically filled in!

![redeem-script page](/docs/images/redeemscript.jpg)

_Now_ send some bitcoins to your multisignature address. In this case 0.01 Bitcoins were sent to `3NAhQbKxDDGzfy8i1ssAWgePZfYkpsxKGA`.

* * *

**Donations are welcome:** 3Q1kpuG9ewSa1Sj7gK9NSJGdrsf2LEL7Sx (multisignature address!)

0427daf910ec09dea5fd0ced5d2f0fe8c07eabef12f909e7d64da526edd10be8a5e9182b9c0c0f36584b4815c89cf4d8d3163643861342244b026933a723926e98
04d599b7ddcfbfa67cbedd78131ca8ee6c8955f644b9e5c38659a6761b91f5605c81d7baa2da6e5d28f2598aabf4bb91631b382e54a007c671d77e084fa2785f1a
04be4557a1009fd8f85ccf822314ac13d2ff7b40b60d260652ceac7a1e1f718904f989b9891a2493da127f94fad42b7c6d1fa3c4fd577982186d88cb22705f7f3c

53410427daf910ec09dea5fd0ced5d2f0fe8c07eabef12f909e7d64da526edd10be8a5e9182b9c0c0f36584b4815c89cf4d8d3163643861342244b026933a723926e984104be4557a1009fd8f85ccf822314ac13d2ff7b40b60d260652ceac7a1e1f718904f989b9891a2493da127f94fad42b7c6d1fa3c4fd577982186d88cb22705f7f3c4104d599b7ddcfbfa67cbedd78131ca8ee6c8955f644b9e5c38659a6761b91f5605c81d7baa2da6e5d28f2598aabf4bb91631b382e54a007c671d77e084fa2785f1a53ae

3NAhQbKxDDGzfy8i1ssAWgePZfYkpsxKGA
