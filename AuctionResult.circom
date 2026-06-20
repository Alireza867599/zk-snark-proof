pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/escalarmulany.circom";

/*
  AuctionResultCommitmentProofCore.circom

  Exact-size Proof B template.

  This is NOT a 100-bidder padded circuit.
  A generator creates a size-specific main component:

      AuctionResultCommitmentProofExact(NB, NS, 252)

  Example:
      NB = 4, NS = 3
      => generated circuit only has constraints for 4 buyers and 3 sellers.

  Proof B proves:
    1. Vector hash consistency:
       Poseidon(permutation vector) == public permutationHash
       Poseidon(share-bid vector) == public shareBidVectorHash
       Poseidon(randomness vector) == public randomnessVectorHash

    2. Share-bid commitment openings:
       C = shareBid * G + randomness * H

    3. Reconstructed full bids/asks:
       buyerBid[i]  = p0BuyerShare[i]  + p1BuyerShare[i] mod 2^64
       sellerAsk[j] = p0SellerShare[j] + p1SellerShare[j] mod 2^64

    4. Selected permutation:
       targetPartyId = 0 -> use P0 permutation
       targetPartyId = 1 -> use P1 permutation

    5. Auction-result rule:
       K = largest k such that B_k >= V_k and B_k != B_{k-1}
       For k=1, B_k != B_{k-1} is ignored.
       Pb = B_K, Ps = V_K
       winners = first K - 1 buyers/sellers.

  Public signal layout is generated/used by JS and Solidity:

    0 sessionId
    1 targetPartyId
    2 K
    3 Pb
    4 Ps

    5.. winnerBuyerIds[MAX_WINNERS]
    then winnerSellerIds[MAX_WINNERS]

    then 16 vector-hash public signals:
      p0Buyer: permutation, share, randomness, signedMessage
      p1Buyer: permutation, share, randomness, signedMessage
      p0Seller: permutation, share, randomness, signedMessage
      p1Seller: permutation, share, randomness, signedMessage

    then commitment points:
      buyerC0x/y, buyerC1x/y for each buyer
      sellerC0x/y, sellerC1x/y for each seller

    then buyerIds[NB], sellerIds[NS]
*/

template U64ModAdd() {
    var TWO64 = 18446744073709551616;

    signal input a;
    signal input b;
    signal input carry;
    signal output out;

    carry * (carry - 1) === 0;

    out <-- a + b - carry * TWO64;

    component aBits = Num2Bits(64);
    component bBits = Num2Bits(64);
    component outBits = Num2Bits(64);

    aBits.in <== a;
    bBits.in <== b;
    outBits.in <== out;

    a + b === out + carry * TWO64;
}

template ApplyPermutation(N) {
    signal input values[N];
    signal input perm[N];

    signal output selected[N];

    component eq[N][N];
    signal product[N][N];

    for (var outIdx = 0; outIdx < N; outIdx++) {
        for (var inIdx = 0; inIdx < N; inIdx++) {
            eq[outIdx][inIdx] = IsEqual();
            eq[outIdx][inIdx].in[0] <== perm[outIdx];
            eq[outIdx][inIdx].in[1] <== inIdx + 1;

            product[outIdx][inIdx] <== eq[outIdx][inIdx].out * values[inIdx];
        }

        var acc = 0;

        for (var inIdx = 0; inIdx < N; inIdx++) {
            acc += product[outIdx][inIdx];
        }

        selected[outIdx] <== acc;
    }
}

template SelectPermutation(N) {
    signal input selectP1;
    signal input p0Perm[N];
    signal input p1Perm[N];

    signal output selected[N];

    signal diff[N];
    signal mix[N];

    for (var i = 0; i < N; i++) {
        diff[i] <== p1Perm[i] - p0Perm[i];
        mix[i] <== selectP1 * diff[i];
        selected[i] <== p0Perm[i] + mix[i];
    }
}

template VectorHashCheck(N) {
    signal input permutation[N];
    signal input shareBidVector[N];
    signal input randomnessVector[N];

    signal input permutationHash;
    signal input shareBidVectorHash;
    signal input randomnessVectorHash;

    component permHasher = Poseidon(N);
    component shareHasher = Poseidon(N);
    component randHasher = Poseidon(N);

    for (var i = 0; i < N; i++) {
        permHasher.inputs[i] <== permutation[i];
        shareHasher.inputs[i] <== shareBidVector[i];
        randHasher.inputs[i] <== randomnessVector[i];
    }

    permHasher.out === permutationHash;
    shareHasher.out === shareBidVectorHash;
    randHasher.out === randomnessVectorHash;
}

template ScalarMulPoint(NBITS) {
    signal input scalar;
    signal input px;
    signal input py;

    signal output x;
    signal output y;

    component bits = Num2Bits(NBITS);
    bits.in <== scalar;

    component mul = EscalarMulAny(NBITS);

    for (var i = 0; i < NBITS; i++) {
        mul.e[i] <== bits.out[i];
    }

    mul.p[0] <== px;
    mul.p[1] <== py;

    x <== mul.out[0];
    y <== mul.out[1];
}

template CommitmentOpenCheck(RBITS) {
    /*
      Commitment equation:
          C = shareBid * G + randomness * H

      These constants match your fixed commitment domain:
          SFDAC-BabyJub-Pedersen-v1
    */

    var COMMIT_G_X = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    var COMMIT_G_Y = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    var COMMIT_H_X = 7366807606633366341510211603899644485442612417275237302109498669203270798653;
    var COMMIT_H_Y = 13018880452790947008889832553359497231246615770556373976243907597581451480432;

    signal input shareBid;
    signal input randomness;

    signal input Cx;
    signal input Cy;

    component shareMulG = ScalarMulPoint(64);
    shareMulG.scalar <== shareBid;
    shareMulG.px <== COMMIT_G_X;
    shareMulG.py <== COMMIT_G_Y;

    component randMulH = ScalarMulPoint(RBITS);
    randMulH.scalar <== randomness;
    randMulH.px <== COMMIT_H_X;
    randMulH.py <== COMMIT_H_Y;

    component add = BabyAdd();

    add.x1 <== shareMulG.x;
    add.y1 <== shareMulG.y;
    add.x2 <== randMulH.x;
    add.y2 <== randMulH.y;

    add.xout === Cx;
    add.yout === Cy;
}

template AuctionResultCommitmentProofExact(NB, NS, RBITS) {
    var T = NB < NS ? NB : NS;
    var W = T - 1;

    // private signed vectors
    signal input p0BuyerPermutation[NB];
    signal input p0BuyerShareBidVector[NB];
    signal input p0BuyerRandomnessVector[NB];

    signal input p1BuyerPermutation[NB];
    signal input p1BuyerShareBidVector[NB];
    signal input p1BuyerRandomnessVector[NB];

    signal input p0SellerPermutation[NS];
    signal input p0SellerShareBidVector[NS];
    signal input p0SellerRandomnessVector[NS];

    signal input p1SellerPermutation[NS];
    signal input p1SellerShareBidVector[NS];
    signal input p1SellerRandomnessVector[NS];

    // carries for reconstructing full bids/asks modulo 2^64
    signal input buyerFullBidCarry[NB];
    signal input sellerFullBidCarry[NS];

    // public base
    signal input sessionId;
    signal input targetPartyId;

    signal input K;
    signal input Pb;
    signal input Ps;

    signal input winnerBuyerIds[W];
    signal input winnerSellerIds[W];

    // public vector hashes
    signal input p0BuyerPermutationHash;
    signal input p0BuyerShareBidVectorHash;
    signal input p0BuyerRandomnessVectorHash;
    signal input p0BuyerSignedMessageHash;

    signal input p1BuyerPermutationHash;
    signal input p1BuyerShareBidVectorHash;
    signal input p1BuyerRandomnessVectorHash;
    signal input p1BuyerSignedMessageHash;

    signal input p0SellerPermutationHash;
    signal input p0SellerShareBidVectorHash;
    signal input p0SellerRandomnessVectorHash;
    signal input p0SellerSignedMessageHash;

    signal input p1SellerPermutationHash;
    signal input p1SellerShareBidVectorHash;
    signal input p1SellerRandomnessVectorHash;
    signal input p1SellerSignedMessageHash;

    // public commitment points and IDs
    signal input buyerC0x[NB];
    signal input buyerC0y[NB];
    signal input buyerC1x[NB];
    signal input buyerC1y[NB];

    signal input sellerC0x[NS];
    signal input sellerC0y[NS];
    signal input sellerC1x[NS];
    signal input sellerC1y[NS];

    signal input buyerIds[NB];
    signal input sellerIds[NS];

    // targetPartyId must be 0 or 1
    component targetIs0 = IsEqual();
    component targetIs1 = IsEqual();

    targetIs0.in[0] <== targetPartyId;
    targetIs0.in[1] <== 0;

    targetIs1.in[0] <== targetPartyId;
    targetIs1.in[1] <== 1;

    targetIs0.out + targetIs1.out === 1;

    // vector hash checks
    component p0BuyerHash = VectorHashCheck(NB);
    component p1BuyerHash = VectorHashCheck(NB);

    for (var i = 0; i < NB; i++) {
        p0BuyerHash.permutation[i] <== p0BuyerPermutation[i];
        p0BuyerHash.shareBidVector[i] <== p0BuyerShareBidVector[i];
        p0BuyerHash.randomnessVector[i] <== p0BuyerRandomnessVector[i];

        p1BuyerHash.permutation[i] <== p1BuyerPermutation[i];
        p1BuyerHash.shareBidVector[i] <== p1BuyerShareBidVector[i];
        p1BuyerHash.randomnessVector[i] <== p1BuyerRandomnessVector[i];
    }

    p0BuyerHash.permutationHash <== p0BuyerPermutationHash;
    p0BuyerHash.shareBidVectorHash <== p0BuyerShareBidVectorHash;
    p0BuyerHash.randomnessVectorHash <== p0BuyerRandomnessVectorHash;

    p1BuyerHash.permutationHash <== p1BuyerPermutationHash;
    p1BuyerHash.shareBidVectorHash <== p1BuyerShareBidVectorHash;
    p1BuyerHash.randomnessVectorHash <== p1BuyerRandomnessVectorHash;

    component p0SellerHash = VectorHashCheck(NS);
    component p1SellerHash = VectorHashCheck(NS);

    for (var j = 0; j < NS; j++) {
        p0SellerHash.permutation[j] <== p0SellerPermutation[j];
        p0SellerHash.shareBidVector[j] <== p0SellerShareBidVector[j];
        p0SellerHash.randomnessVector[j] <== p0SellerRandomnessVector[j];

        p1SellerHash.permutation[j] <== p1SellerPermutation[j];
        p1SellerHash.shareBidVector[j] <== p1SellerShareBidVector[j];
        p1SellerHash.randomnessVector[j] <== p1SellerRandomnessVector[j];
    }

    p0SellerHash.permutationHash <== p0SellerPermutationHash;
    p0SellerHash.shareBidVectorHash <== p0SellerShareBidVectorHash;
    p0SellerHash.randomnessVectorHash <== p0SellerRandomnessVectorHash;

    p1SellerHash.permutationHash <== p1SellerPermutationHash;
    p1SellerHash.shareBidVectorHash <== p1SellerShareBidVectorHash;
    p1SellerHash.randomnessVectorHash <== p1SellerRandomnessVectorHash;

    // commitment checks for every buyer share
    component buyerC0Check[NB];
    component buyerC1Check[NB];

    for (var bi = 0; bi < NB; bi++) {
        buyerC0Check[bi] = CommitmentOpenCheck(RBITS);
        buyerC0Check[bi].shareBid <== p0BuyerShareBidVector[bi];
        buyerC0Check[bi].randomness <== p0BuyerRandomnessVector[bi];
        buyerC0Check[bi].Cx <== buyerC0x[bi];
        buyerC0Check[bi].Cy <== buyerC0y[bi];

        buyerC1Check[bi] = CommitmentOpenCheck(RBITS);
        buyerC1Check[bi].shareBid <== p1BuyerShareBidVector[bi];
        buyerC1Check[bi].randomness <== p1BuyerRandomnessVector[bi];
        buyerC1Check[bi].Cx <== buyerC1x[bi];
        buyerC1Check[bi].Cy <== buyerC1y[bi];
    }

    // commitment checks for every seller share
    component sellerC0Check[NS];
    component sellerC1Check[NS];

    for (var si = 0; si < NS; si++) {
        sellerC0Check[si] = CommitmentOpenCheck(RBITS);
        sellerC0Check[si].shareBid <== p0SellerShareBidVector[si];
        sellerC0Check[si].randomness <== p0SellerRandomnessVector[si];
        sellerC0Check[si].Cx <== sellerC0x[si];
        sellerC0Check[si].Cy <== sellerC0y[si];

        sellerC1Check[si] = CommitmentOpenCheck(RBITS);
        sellerC1Check[si].shareBid <== p1SellerShareBidVector[si];
        sellerC1Check[si].randomness <== p1SellerRandomnessVector[si];
        sellerC1Check[si].Cx <== sellerC1x[si];
        sellerC1Check[si].Cy <== sellerC1y[si];
    }

    // reconstruct full bids/asks
    component addBuyer[NB];
    signal buyerFullBid[NB];

    for (var rb = 0; rb < NB; rb++) {
        addBuyer[rb] = U64ModAdd();
        addBuyer[rb].a <== p0BuyerShareBidVector[rb];
        addBuyer[rb].b <== p1BuyerShareBidVector[rb];
        addBuyer[rb].carry <== buyerFullBidCarry[rb];

        buyerFullBid[rb] <== addBuyer[rb].out;
    }

    component addSeller[NS];
    signal sellerFullAsk[NS];

    for (var rs = 0; rs < NS; rs++) {
        addSeller[rs] = U64ModAdd();
        addSeller[rs].a <== p0SellerShareBidVector[rs];
        addSeller[rs].b <== p1SellerShareBidVector[rs];
        addSeller[rs].carry <== sellerFullBidCarry[rs];

        sellerFullAsk[rs] <== addSeller[rs].out;
    }

    // select target permutations
    component selectBuyerPerm = SelectPermutation(NB);
    selectBuyerPerm.selectP1 <== targetIs1.out;

    for (var bp = 0; bp < NB; bp++) {
        selectBuyerPerm.p0Perm[bp] <== p0BuyerPermutation[bp];
        selectBuyerPerm.p1Perm[bp] <== p1BuyerPermutation[bp];
    }

    component selectSellerPerm = SelectPermutation(NS);
    selectSellerPerm.selectP1 <== targetIs1.out;

    for (var sp = 0; sp < NS; sp++) {
        selectSellerPerm.p0Perm[sp] <== p0SellerPermutation[sp];
        selectSellerPerm.p1Perm[sp] <== p1SellerPermutation[sp];
    }

    // apply selected permutations to bid values and IDs
    component applyBuyerBidPerm = ApplyPermutation(NB);
    component applyBuyerIdPerm = ApplyPermutation(NB);

    for (var ab = 0; ab < NB; ab++) {
        applyBuyerBidPerm.values[ab] <== buyerFullBid[ab];
        applyBuyerBidPerm.perm[ab] <== selectBuyerPerm.selected[ab];

        applyBuyerIdPerm.values[ab] <== buyerIds[ab];
        applyBuyerIdPerm.perm[ab] <== selectBuyerPerm.selected[ab];
    }

    component applySellerAskPerm = ApplyPermutation(NS);
    component applySellerIdPerm = ApplyPermutation(NS);

    for (var as = 0; as < NS; as++) {
        applySellerAskPerm.values[as] <== sellerFullAsk[as];
        applySellerAskPerm.perm[as] <== selectSellerPerm.selected[as];

        applySellerIdPerm.values[as] <== sellerIds[as];
        applySellerIdPerm.perm[as] <== selectSellerPerm.selected[as];
    }

    // auction rule over T = min(NB, NS)
    component ge[T];
    component eqPrev[T];

    signal valid[T];

    for (var k = 0; k < T; k++) {
        ge[k] = LessEqThan(64);
        ge[k].in[0] <== applySellerAskPerm.selected[k];
        ge[k].in[1] <== applyBuyerBidPerm.selected[k];

        if (k == 0) {
            valid[k] <== ge[k].out;
        } else {
            eqPrev[k] = IsEqual();
            eqPrev[k].in[0] <== applyBuyerBidPerm.selected[k];
            eqPrev[k].in[1] <== applyBuyerBidPerm.selected[k - 1];

            valid[k] <== ge[k].out * (1 - eqPrev[k].out);
        }
    }

    // suffixHasValid[i] = OR(valid[i], valid[i+1], ..., valid[T-1])
    signal suffixHasValid[T + 1];
    suffixHasValid[T] <== 0;

    for (var rr = 0; rr < T; rr++) {
        var i = T - 1 - rr;
        suffixHasValid[i] <== valid[i] + suffixHasValid[i + 1] - valid[i] * suffixHasValid[i + 1];
    }

    signal isMaxK[T];

    for (var mk = 0; mk < T; mk++) {
        isMaxK[mk] <== valid[mk] * (1 - suffixHasValid[mk + 1]);
    }

    var kAcc = 0;

    for (var kk = 0; kk < T; kk++) {
        kAcc += (kk + 1) * isMaxK[kk];
    }

    K === kAcc;

    // K must be in [0..T]
    component kIs[T + 1];

    var kFlagSum = 0;

    for (var kv = 0; kv <= T; kv++) {
        kIs[kv] = IsEqual();
        kIs[kv].in[0] <== K;
        kIs[kv].in[1] <== kv;

        kFlagSum += kIs[kv].out;
    }

    kFlagSum === 1;

    // Pb/Ps = B_K/V_K, or 0 if K=0.
    //
    // Each multiplication must be constrained separately. If we put many
    // products directly inside Pb === ..., Circom reports a non-quadratic
    // constraint.
    signal pbTerm[T];
    signal psTerm[T];

    for (var pk = 1; pk <= T; pk++) {
        pbTerm[pk - 1] <== kIs[pk].out * applyBuyerBidPerm.selected[pk - 1];
        psTerm[pk - 1] <== kIs[pk].out * applySellerAskPerm.selected[pk - 1];
    }

    var pbAcc = 0;
    var psAcc = 0;

    for (var pk2 = 0; pk2 < T; pk2++) {
        pbAcc += pbTerm[pk2];
        psAcc += psTerm[pk2];
    }

    Pb === pbAcc;
    Ps === psAcc;

    // Winners are first K-1 buyers/sellers.
    // For index w, it is active if w + 2 <= K.
    component winnerActive[W];

    signal buyerWinnerTerm[W];
    signal sellerWinnerTerm[W];

    for (var w = 0; w < W; w++) {
        winnerActive[w] = LessEqThan(16);
        winnerActive[w].in[0] <== w + 2;
        winnerActive[w].in[1] <== K;

        buyerWinnerTerm[w] <== winnerActive[w].out * applyBuyerIdPerm.selected[w];
        sellerWinnerTerm[w] <== winnerActive[w].out * applySellerIdPerm.selected[w];

        winnerBuyerIds[w] === buyerWinnerTerm[w];
        winnerSellerIds[w] === sellerWinnerTerm[w];
    }
}
