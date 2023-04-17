# Summary

This post aims to provide a curated list of some of the most common vulnerabilities that might affect Cardano applications leveraging Plutus scripts. Its purpose is to help developers avoid some of the common pitfalls when designing and implementing their applications, as well as provide a reference to help auditors look for potential vulnerabilities in a systematic way.

Each vulnerability is described by a **Property statement** that must hold for the vulnerability to be absent, a **Test** that represents reputation of said property and the potential **Impacts** that could be caused by the described vulnerability. In order to help identify the vulnerability, where applicable a minimal code example containing it is provided.

In an effort to provide a framework that let auditors document and classify their findings in a standard way, and hopefully help with communication among different stakeholders, a list of potential **Impacts** along with their description is attached (see below).

Note that it is not always obvious how to name vulnerabilities, as sometimes they are named by their ‘cause’ (eq. unsafe SQL expression concatenation), and sometimes by what they enable (eq. SQL injection) and sometimes by their impact (eq. User passwords disclosed).

## Glossary

- Protocol is the totality of validators, minting policies, outputs, datum and values, users and actors that are in some way related together by the application design.
- Plutus script is a generic word to refer both to validators and minting policies.
- The term “Foreign” can mean anything not belonging to the Protocol.
- A "legit UTxO" is an output that was expected to be locked by a script as part of the correct functioning of the protocol.

## List of Impacts

1. **By-passing checks** - Some checks that should be performed by the Plutus program can be avoided.
2. **Leaking protocol tokens** - Tokens that should be exclusively managed by the protocol can be sent to some non-protocol address.
3. **Unauthorised protocol actions** - It is possible to perform a protocol action without satisfying the intended requirements.
4. **Unspendable outputs** - UTxOs cannot be spent by any transaction due to a logic dead-lock or resource exhaustion.
5. **Protocol stalling** - The rate at which the protocol operates is degraded.
6. **Protocol halting** - The protocol cannot evolve any further.
7. **Unpredictable addresses** - The address of a script cannot be known in advance.
8. **Illegitimate staking rewards** - ADA staking rewards are unintentionally granted to an actor different from the owner of the staked ADA. 

# List of common Plutus vulnerabilites
1. [Other redeemer](#1-other-redeemer)
2. [Other token name](#2-other-token-name)
3. [Unbounded Datum](#3-unbounded-datum)
4. [Arbitrary Datum](#4-arbitrary-datum)
5. [Unbounded value](#5-unbounded-value)
6. [Multiple satisfaction](#6-multiple-satisfaction)
7. [Missing UTxO authentication](#7-missing-utxo-authentication)
8. [UTxO contention](#8-utxo-contention)
9. [Cheap spam](#9-cheap-spam)
10. [Insufficient staking key control](#10-insuficient-staking-key-control)

## 1. Other redeemer

### Identifier
other-redeemer

### Property statement
Logic under one script redeemer that relies on the logic enforced by another redeemer (either from the same script or from another one) explicitly requires the presence of the Redeemer under which the intended logic exists.

### Test
A transaction can successfully avoid some checks by spending a UTxO or minting a token using a different redeemer than the one expected by the script.

### Impact
- By-passing checks

### Further explanation
Let us say that we have a simple staking protocol that allows users to lock a certain amount of token X and later on receive an ADA reward, which increases based on the amount of time tokens have been locked. This protocol consists of two validators, `globalValidator` and `positionsValidator`. The `globalValidator`'s mission is to lock an NFT that carries as Datum the global state of the pool (e.g. how much token X has been staked in aggregate by all participants) as well as the rewards pool (ADA to be distributed to stakers) and the `positionsValidator`'s mission is to lock one UTxO per each participant, holding the user's bag of token X and carrying as Datum a timestamp stating when was the last time that the position was updated.

To interact with the protocol, users can either open a position or update their position.

To reflect that, the validators have the following logic:
 - `globalValidator` has one redeemer, `UpdateState`, which checks that a user's position is opened or updated correctly and that rewards are distributed correctly based on the user's stake size and timestamp, updating the global state accordingly.

 - `positionsValidator` has one redeemer, `UpdatePosition`, which just checks that the NFT locked in `globalValidator` has been consumed, therefore deferrings all the checking to the `globalValidator`.

Some time after, a new redeemer is added to `globalValidator` to allow anyone to add ADA to the rewards pool. This new redeemer, `AddRewards`, only verifies that the consumed UTxO is locked back in the same validator keeping the same Datum, but with an increased amount of ADA.

By adding this new redeemer, a vulnerability has been introduced. This is because by consuming the UTxO locked in the `globalValidator` with the `AddRewards` redeemer, nothing is checked regarding the correct update of the user's position. Therefore, in the same transaction a user could freely update their position, for instance changing the timestamp to some time far away in the past. This would allow the user to, in a second transaction, fool the `globalValidator` to unlock a big chunk of the rewards pool.

## 2. Other token name

### Identifier
other-token-name

### Property statement
A minting policy checks that the total value minted of its ‘own’ currency symbol does not include unintended token names.

### Test
A transaction can successfully mint a token with token name different than the intended one.

### Impacts
- Leaking protocol tokens
- Unauthorised protocol actions

### Further explanation
A common coding pattern that introduces such a vulnerability can be observed in the following excerpt:

```haskell
myPolicy par red ctx = do
  …
  assetClassValueOf txInfoMint ownAssetClass == someQuantity
  …
```

Note that on Cardano, a token is defined by its asset class, which consist of two parts: the currency symbol and the token name. The currency symbol is the hash of the minting policy containing the rules controlling the minting and burning of the token. The token name can be any string with a maximum length of 32 bytes.

The above minting policy checks that a specific asset class is found within the value minted by the transaction. If we were to trust that the minting policy is controlling that only `someQuantity` of tokens with the currency symbol controlled by the minting policy ('own' currency symbol) are being minted, we would be making a big mistake. This is because the minting policy is only checking that `someQuantity` of tokens with 'own' currency symbol and **a specific token name** are being minted, but nothing is checked for other token names. Therefore, someone could maliciously mint a token with a different token name and use it, for instance, to impersonate the owner of the legit token.

The most straight-forward coding pattern to use in order to prevent such a vulnerability can be observed in the following excerpt:

```haskell
myPolicy rmr ctx = do
   …
   txInfoMint == (assetClassValue ownAssetClass someQuantity)
  …
```

The fixed minting policy checks that only `someQuantity` of tokens are being minted, and all of them have the same asset class. Of course, this might be too restrictive if tokens with other currency symbols need to be minted in the same transaction. If this is the case, a slightly more complex solution will be needed.

## 3. Unbounded Datum

### Identifier
unbounded-datum

### Property statement
Datum for all legit UTxOs locked by the protocol have an upper bound for their size, and the upper bound is low enough to not prevent consumption of the UTxO as an input in a future transaction. 

### Test
A transaction can successfully lock in the protocol a legit UTxO with a Datum such that its consumption in a second transaction fails due to reaching the network resources constraints.

### Impacts
- Unspendable outputs
- Protocol halting

### Further explanation
A common design pattern that introduces such vulnerability can be observed in the following excerpt:

```haskell
data MyDatum = Foo {
  users :: [String],
  userToPkh :: Map String PubKeyHash
}
```
If the protocol allows `MyDatum` to grow indefinitely, eventually memory and CPU usage limits and/or size limits imposed by the Plutus interpreter will be reached, rendering the output unspendable.

Note that although inline Datum for the inputs of a transaction do not contribute to its size (unlike a non-inline Datum, as it must be attached), they still might contribute to increase the memory and CPU usage depending on the validator's logic.

The recommended design patterns are either to limit the growth of such datum in validators or to split the datum across different outputs.

## 4. Arbitrary Datum

### Identifier
arbitrary-datum

### Property statement
Correctness of the Datum is checked for all legit UTxOs locked by the protocol.

### Test
A transaction can successfully lock in the protocol a legit UTxO with an arbitrary Datum, making consumption in a second transaction fail.

### Impact
- Unspendable outputs
- Protocol halting

### Further explanation
It could be tempting to omit checks for the Datum of an output being locked in a script when this Datum is not going to be explicitly used in the validation of the future spending transaction. However, this is a dangerous practice as the type of the Datum carried by a UTxO locked in a validator still needs to match the Datum type expected by the validator. Otherwise, a transaction trying to consume the locked UTxO will fail, even if nothing was going to be checked about the information contained in the Datum.

## 5. Unbounded value

### Identifier
unbounded-value

### Property statement
Values of all legit UTxOs locked by the protocol have an upper bound for their size, and the upper bound is low enough to not prevent consumption of the UTxO as an input in a future transaction.

### Test
A transaction can successfully lock in the protocol a legit UTxO with a value large enough to make its consumption fail due to reaching the network resources constraints.

### Impact
- Unspendable outputs
- Protocol halting

### Further explanation
Typically, a large value could make a transaction fail in two ways:

- If an input UTxO has N native tokens in the value, then just by passing on the input values to the output and adding some M additional tokens, the transaction might fail due to exceeding the transaction size limit.

- If the input UTxO contains a lot of different native tokens and the script logic is such that it must go through and process them, then the transaction might fail due to execution resources (XU limits) being breached.

Note that values held by UTxOs only contribute to the size of the transaction when being part of the outputs of the transaction, but not when they are part of the inputs.

A common case where this problem arises is when the logic of the scripts allow the presence and addition of foreign tokens (i.e. tokens not expected by the protocol).

## 6. Multiple satisfaction

### Identifier
multiple-satisfaction

### Property statement
All scripts consider the totality of inputs to the transaction when allowing spending or minting of value.

### Test
A transaction consumes multiple UTxOs, successfully spending or minting the value attributed to each individual UTxO and respecting the conditions under which the value could be spent or minted for each individual UTxO, but without respecting the intended aggregate conditions under which the totality of the value could be spent or minted.

### Impact
- Leaking protocol tokens
- Unauthorised protocol actions

### Further explanation
A common coding pattern that introduces such a vulnerability can be observed in the following excerpt:

```haskell
vulnValidator _ _ ctx = 
  ownInput ← findOwnInput ctx
  ownOutput ← findContinuingOutput ctx
  traceIfFalse “Must continue tokens” (valueIn ownInput == valueIn ownOutput)
```

The above validator ensures that tokens held by a consumed UTxO ('own input') are present in an output that is locked back in the validator ('continuing output' or 'own output').

Although the logic is correct when considering validation for each UTxO in isolation, things can go wrong when consuming multiple UTxOs from the same script in the same transaction.

For instance, let us consider the the case where there are two outputs at `vulnValidator` holding the same values:

Output A - TxOut ($FOO x 1 + $ADA x 2)
Output B - TxOut ($FOO x 1 + $ADA x 2)

A transaction that spends both of these outputs can steal the value held by one of them by simply paying $FOO x 1 + $ADA x 2 back to the address corresponding to `vulnValidator` and paying the rest $FOO x 1 + $ADA x 2 to an arbitrary address.

More can be read about this vulnerability [in the Plutus docs](https://plutus.readthedocs.io/en/latest/reference/writing-scripts/common-weaknesses/double-satisfaction.html).

## 7. Missing UTxO authentication

### Identifier
missing-utxo-authentication

### Property statement
All spending and referencing of legit protocol outputs is authenticated.

### Test
A transaction can successfully spend or reference an illegitimate protocol output.

### Impact
- Unauthorised protocol actions

### Further explanation
This vulnerability can easily be illustrated by using oracles as an example.

Let us imagine that we have a protocol that relies on information about the real world to allow or disallow certain actions. For instance, an insurance company could allow spending from a pool of funds if some natural disaster such as an earthquake or a hurricane had hit a certain region in the last 30 days. In order for the validator locking the funds (`insuranceVal`) to know whether such a natural disaster has occured, it relies on the information given by an oracle.

The way the oracle provides the information is by locking in the oracle validator (`oracleVal`) a UTxO carrying as datum the latest date when a natural disaster happened in a certain region.

A naive implementation of `insuranceVal` could be to search for an input coming from `oracleVal`, read the information stored in the datum and decide whether to allow spending or not based on that information.

However, by using this approach it would be very easy to fool `insuranceVal` to unlock the funds. This is due to the nature of validators on Cardano, which only validate the consumption of UTxOs locked by them, but do not control the locking of outputs. This means that anybody can send funds to a validator's address, effectively locking all kinds of UTxOs. In the context of our example, this means that anybody could lock a UTxO carrying as datum false information, for instance stating that a hurricane happened in the last week. This would fool `insuranceVal` to allow spending of the funds.

In order to prevent this, the legit UTxO in `oracleVal` that holds the real information provided by the oracle should be authenticated. One way of achieving this would be to hold a specific non-fungible token (`oracleNFT`) as part of the value. Now, instead of searching for an input coming from `oracleVal`, `insuranceVal` could safely look for an input holding `oracleNFT`, which is unique.

## 8. UTxO contention

### Identifier
utxo-contention

### Property statement
The protocol is designed in such a way that disincentivises the attempt to consume the same UTxO by multiple actors.

### Test
One out of two or more transactions trying to consume the same UTxO fails due to the UTxO not existing anymore.

### Impact
- Protocol stalling
- Protocol halting

### Further explanation
This vulnerability is very common in the case where a UTxO carries some global datum or shared value (global state).

For instance, a decentralised exchange (DEX) that holds in a single UTxO (global UTxO) the pool of assets available to be swapped would experience a high degree of contention, since every swap would require consuming the global UTxO and recreating it by locking back the pool of assets with the swap already performed. In practice, this would make the DEX unusable, since as soon as it becomes popular and volume of transactions is significant, the global UTxO would be unavailable for most of the users.

Protocols that aim to minimise this vulnerability should aim for parallel transactions and distributed state management wherever possible.

## 9. Cheap spam

### Identifier
cheap-spam

### Property statement
All intended actions can be performed in a timely manner under the assumption that nobody is willing to spend more resources than the potential gain by denying service of the protocol.

### Test
A denial of service status is achieved by introducing many actions that interfere with the intended use of the protocol, making it impossible to consume the target UTxO in a timely manner.

### Impact
- Protocol stalling
- Protocol halting

### Further explanation
Stalling is problematic when the cost to stall is lower than the loss of opportunity cost it causes i.e. by spending n Ada you cause the protocol to loose m Ada where m > n. Usually this snowballs, especially in financially incentivised protocols because people lose trust and then it all amplifies.

For instance, if the solvency of a lending protocol depends on liquidations of debt to be performed in a timely manner, it is important to make sure that there are no actions such as creating many small and undercollateralised debt positions that would delay liquidation of a big debt position. 

Note that the combination of this vulnerabilty with utxo-contention increases its severity, as it would be easier to deny service to a single UTxO.

## 10. Insuficient staking key control

### Identifier
insufficient-staking-control

### Property statement
All scripts explicitly account for staking credentials.

### Test
A transaction successfully changes or incorrectly sets the staking credential of a UTxO locked by a validator of the protocol.

### Impact
- Unpredictable addresses
- Illegitimate staking rewards

### Further explanation
When writing the logic for a Plutus script, it is easy to focus too much on the set of rules that must be enforced by a validator and start thinking of these rules as solely defining the Cardano addresses. This is, treating validator hashes and addresses interchangeably. An example of such behaviour is illustrated by the following excerpt:

```haskell
vulnValidator _ _ ctx = 
  ownInput = findOwnInput ctx
  ownValidatorHash = ownHash ctx
  [(_, contVal)] = scriptOutputsAt ownValidatorHash (scriptContextTxInfo ctx)
  traceIfFalse “Must continue tokens” (valueIn ownInput == contVal)
```

The validator above tries to make sure that after consuming a UTxO locked by `vulnValidator`, an output holding the same value is locked back. However, it forgets about the staking credentials, so the output can actually be locked in a very large number of addresses.

This is because addresses are composed of credentials that control the spending of UTxOs AND staking credentials that control the claiming of ADA staking rewards. Therefore, validation would succeed as long as the output is locked in an address which has `ownHash` as credential. However, there are as many such addresses as possible public keys for a staking credential.

By exploiting this, anybody could send the funds to an address with a staking credential control by them. This would not grant them control over the funds, since they are still guarded by the validator's logic, but would grant them control over the staking rewards generated by all the ADA present in the locked output.

Apart from losing control over staking rewards, ignoring the staking credentials could have further consequences and result in a catastrophic outcome. This is because since the UTxO holding the funds can live in a big spectrum of addresses, it becomes more difficult to reason about the rules that control their spending.

For instance, to prevent a multiple-satisfaction attack, a validator could have a rule ensuring that only one input coming from the address of the input being validated is present in the transaction. This works correctly assuming that all relevant funds are locked in the same address as the input being validated. However, as soon as part of the funds end up in an address with the same credential but different staking credential, the check could be by-passed and tokens could leak.
