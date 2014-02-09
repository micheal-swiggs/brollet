
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

_Now_ send some bitcoins to your multisignature address. In this case 0.01 Bitcoins was sent to 3NAhQbKxDDGzfy8i1ssAWgePZfYkpsxKGA .

# Spending from multisig address

_Open_ up Multisignature Spend page by clicking `Spend` on the home page. You will then paste the redeem-script. Decide where to send the bitcoins. Brollet will then ask you to sign the transaction, click `Sign`.

You will then see the hex form of the transaction in `Encoded Transaction`. Make a copy of this.

![spend page](/docs/images/spend.jpg)

_Next_ open up the Multisignature sign page. Enter the transaction hex from the previous step. You will be able to see the transaction details. Sign the transaction again resulting in 2 of 3 required signatures.

![sign page](/docs/images/sign.jpg)

Copy the transaction hex from the `Encoded Transaction` field into the `Transaction Hex` field. You should see that the transaction only requires one more signing. Once you have signed the third time brollet will ask you to broadcast the transaction.

Congratulations on your first Multisignature transaction!

* * *

**Donations are welcome:** 3Q1kpuG9ewSa1Sj7gK9NSJGdrsf2LEL7Sx (multisignature address!)
