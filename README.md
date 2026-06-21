# zk-snark-proof
this is some part of my project , it contains circom and solidity code for generating and verifying zk-snark proof about validity of auction result  .
Auction Result Commitment Proof

This repository contains the zero-knowledge and on-chain verification layer for proving the correctness of a sealed-bid auction result.

The system is built around a Proof B workflow:

Each auctioneer commits to the proof data during the proof phase.
A public verifier later submits the full Groth16 proof during the verify phase.
The smart contract checks that the submitted proof, public signals, bidder list, vector hashes, bidder commitments, and auction result all match the canonical registry data.
If the proof is invalid or inconsistent, the responsible auctioneer can be slashed.
Files
File	Purpose
AuctionResult.circom	Circom 2 circuit template for proving that the auction result was computed correctly from committed secret-shared bids and selected permutations.
AuctionResultCommitment.sol	Solidity registry contract for commit-then-verify Proof B verification. It checks proof commitments, registry consistency, Groth16 verification, and slashing on failure.

Recommended repository placement:

circuits/
  AuctionResult.circom

contracts/
  AuctionResultCommitmentProofRegistry_2_2.sol
High-Level Architecture

The proof system connects three layers:

Private auction data
        |
        v
Circom Proof B circuit
        |
        v
Groth16 proof + public signals
        |
        v
Solidity Proof B registry
        |
        v
AuctionRegistry + SortingProofRegistry + FailureReporter

The Circom circuit proves the mathematical correctness of the result, while the Solidity contract verifies that the public proof inputs correspond to the data already committed and stored on-chain.

Circom Circuit: AuctionResult.circom

The circuit defines the template:

AuctionResultCommitmentProofExact(NB, NS, RBITS)

For the uploaded Solidity contract, the intended fixed size is:

NB = 2 buyers
NS = 2 sellers
T  = min(NB, NS) = 2
MAX_WINNERS = 1
PUBLIC_SIGNAL_COUNT = 43
What the Circuit Proves

The circuit proves the following:

1. Vector Hash Consistency

For each auctioneer and each side of the market, the circuit checks Poseidon hashes for:

permutation vector
share-bid vector
randomness vector

This binds the private witness data to public vector hash commitments.

2. Commitment Opening Correctness

For every buyer and seller share, the circuit checks that the submitted elliptic-curve commitment opens correctly:

C = shareBid * G + randomness * H

This prevents an auctioneer from proving over share values that do not match the previously published commitments.

3. Bid and Ask Reconstruction

Buyer bids and seller asks are reconstructed from two secret shares:

buyerBid[i]  = p0BuyerShare[i]  + p1BuyerShare[i]  mod 2^64
sellerAsk[j] = p0SellerShare[j] + p1SellerShare[j] mod 2^64

The circuit uses 64-bit range checks and explicit carry inputs to enforce correct modulo reconstruction.

4. Target Permutation Selection

The proof can target either auctioneer:

targetPartyId = 0  -> use P0 permutation
targetPartyId = 1  -> use P1 permutation

The circuit constrains targetPartyId to be either 0 or 1.

5. Auction Result Rule

After applying the selected buyer and seller permutations, the circuit computes the auction result.

The rule implemented is:

K = largest k such that B_k >= V_k and B_k != B_{k-1}

For k = 1, the duplicate-bid condition is ignored.

Then:

Pb = B_K
Ps = V_K
winners = first K - 1 buyers and sellers

If K = 0, then Pb = 0, Ps = 0, and there are no winners.

Public Signals

The Solidity contract expects exactly 43 public signals in the following order:

Index / Range	Meaning
0	sessionId
1	targetPartyId
2	K
3	Pb
4	Ps
5	winnerBuyerIds[0]
6	winnerSellerIds[0]
7..10	P0 buyer hashes: permutation, share-bid, randomness, signed-message
11..14	P1 buyer hashes: permutation, share-bid, randomness, signed-message
15..18	P0 seller hashes: permutation, share-bid, randomness, signed-message
19..22	P1 seller hashes: permutation, share-bid, randomness, signed-message
23..30	Buyer commitment points: C0.x, C0.y, C1.x, C1.y
31..38	Seller commitment points: C0.x, C0.y, C1.x, C1.y
39..40	Buyer IDs
41..42	Seller IDs

The order of these public signals is critical. The witness generator, Circom main component, Solidity verifier, and JavaScript proof-submission code must all use the same ordering.

Solidity Contract: AuctionResultCommitment.sol

The Solidity contract implements the on-chain Proof B registry for the 2-buyer / 2-seller case.

Main contract:

AuctionResultCommitmentProofRegistry_2_2
External Dependencies

The contract depends on four external contracts:

Dependency	Purpose
AuctionRegistry	Stores signed vector hashes, bidder commitments, auction results, phase status, and auctioneer addresses.
CombinedSortingProofRegistry	Confirms that the earlier sorting proof, Proof A, has already been verified.
Groth16Verifier	Verifies the zk-SNARK proof generated from the Circom circuit.
FailureReporter	Handles slashing when Proof B fails.
Commit-Then-Verify Flow

The contract uses a commit-then-verify design.

1. Proof Hash Submission

During the proof phase, the target auctioneer submits three hashes:

proofHash       = keccak256(abi.encode(a, b, c, publicSignals))
publicInputHash = keccak256(abi.encode(publicSignals))
bidderListHash  = keccak256(abi.encode(buyers, sellers))

Only the correct fixed auctioneer may submit the proof commitment:

targetPartyId = 0 -> only P0
targetPartyId = 1 -> only P1

This prevents an auctioneer from changing the proof, public inputs, or bidder list after seeing the verification attempt.

2. Public Verification

During the verify phase, any public participant can submit:

buyer names
seller names
Groth16 proof values a, b, c
the 43 public signals

The contract checks:

The submitted proof hash matches the committed proof hash.
The public input hash matches the committed public input hash.
The bidder list hash matches the committed bidder list hash.
Proof A has already been verified.
The public vector hashes match AuctionRegistry.
The Groth16 proof verifies successfully.
Public commitment points and bidder IDs match AuctionRegistry.
The auction result matches the canonical auction result in AuctionRegistry.
3. Repeated Verification

If the same proof has already been processed, the contract does not revert. Instead, it emits a repeated-verification event and returns the stored result.

This makes the verification process idempotent for the same committed proof.

4. Failure and Slashing

If verification fails after processing begins, the contract calls:

slashAuctioneerForFailedProofB(...)

The failure reason is stored in the proof status and emitted in an event.

Main Contract Functions
Function	Description
submitAuctionResultCommitmentProofHash(...)	Called during proof phase to commit the proof hash, public input hash, and bidder list hash.
verifyAuctionResultCommitmentProof(...)	Called during verify phase to verify the full Proof B proof and public inputs.
hasVerifiedAuctionResultCommitmentProof(...)	Returns whether Proof B has been verified for a session and target party.
hasProcessedAuctionResultCommitmentProof(...)	Returns whether Proof B has already been processed.
getAuctionResultCommitmentProofCommitment(...)	Returns committed and verified proof hashes.
getAuctionResultCommitmentProofStatus(...)	Returns processing, verification, failure, slashing, and auction-result status.
Events
Event	Meaning
AuctionResultCommitmentProofHashSubmitted	A Proof B commitment was submitted.
ProofBVectorHashesChecked	Public vector hashes matched registry data.
ProofBGroth16Checked	The Groth16 proof verified successfully.
ProofBPostProofPublicInputsChecked	Public inputs matched registry commitments and auction results.
AuctionResultCommitmentProofVerified	Proof B was fully verified.
AuctionResultCommitmentProofRepeatedPublicVerification	The same already-processed proof was submitted again.
AuctionResultCommitmentProofFailedAndSlashed	Proof B failed and the auctioneer was slashed.
Security Properties

This design provides the following protections:

Binding to committed data: the proof must match previously submitted vector hashes and bidder commitments.
Binding to bidder identity: the proof is tied to the buyer and seller name arrays through bidderListHash.
No proof substitution: the submitted proof must match the auctioneer's earlier committed proofHash.
No public input substitution: public signals must match the earlier committed publicInputHash.
On-chain consistency: public signals are checked against AuctionRegistry.
Sorting dependency: Proof B is only accepted after Proof A has already been verified.
Accountability: invalid Proof B submissions can trigger slashing.
Suggested Build Flow

Install dependencies:

npm install circomlib snarkjs

Compile the generated exact-size Circom wrapper:

circom circuits/AuctionResult_2_2.circom --r1cs --wasm --sym -o build

Generate the Solidity verifier:

snarkjs zkey export solidityverifier build/AuctionResult_2_2_final.zkey contracts/AuctionResultCommitmentGroth16Verifier_2_2.sol

Compile contracts:

npx hardhat compile
Suggested Verification Flow
Submit bidder share commitments to AuctionRegistry.
Submit signed dataset vector hashes.
Verify the combined sorting proof, Proof A.
During the proof phase, the target auctioneer calls:
submitAuctionResultCommitmentProofHash(...)
During the verify phase, any participant calls:
verifyAuctionResultCommitmentProof(...)
Read final status using:
getAuctionResultCommitmentProofStatus(...)
Development Notes
The Solidity contract is specialized for NB = 2 and NS = 2.
If the number of buyers or sellers changes, regenerate both:
the Circom wrapper / verifier
the Solidity registry constants and public-signal offsets
The public signal layout must stay exactly synchronized across:
Circom
witness generation
JavaScript proof submission
Solidity registry
Groth16 verifier
Run Solidity formatting and compilation before committing the contract.
