 SPDX-License-Identifier MIT
pragma solidity ^0.8.20;

interface IAuctionRegistryForProofBExact_2_2 {
    function hasSignedDatasetVectorHashes(
        uint256 sessionId,
        uint256 datasetKind,
        uint256 partyId
    ) external view returns (bool);

    function getSignedDatasetVectorHashesFlat(
        uint256 sessionId,
        uint256 datasetKind,
        uint256 partyId
    )
        external
        view
        returns (
            bool submitted,
            uint256 permutationHash,
            uint256 shareBidVectorHash,
            uint256 randomnessVectorHash,
            uint256 signedMessageHash,
            address submitter
        );

    function getBidderShareCommitmentsFlat(
        uint256 sessionId,
        string calldata role,
        string calldata name
    )
        external
        view
        returns (
            bool submitted,
            string memory bidderRole,
            string memory bidderName,
            uint256 bidderId,
            string memory commitDomain,
            uint256 c0x,
            uint256 c0y,
            uint256 c1x,
            uint256 c1y,
            address submitter
        );

    function auctionResultsMatch(uint256 sessionId) external view returns (bool);

    function getAuctionResultFlat(
        uint256 sessionId,
        uint256 partyId
    )
        external
        view
        returns (
            bool submitted,
            uint256 K,
            uint256 Pb,
            uint256 Ps,
            uint256[] memory winnerBuyerIds,
            uint256[] memory winnerSellerIds,
            bytes32 winnerBuyerIdsHash,
            bytes32 winnerSellerIdsHash,
            address submitter
        );

    function p0Auctioneer() external view returns (address);
    function p1Auctioneer() external view returns (address);

    function isVerifyPhase(uint256 sessionId) external view returns (bool);
    function isProofPhase(uint256 sessionId) external view returns (bool);
}

interface ICombinedSortingProofRegistryForProofBExact_2_2 {
    function hasVerifiedCombinedSortingProof(
        uint256 sessionId,
        uint256 targetPartyId
    ) external view returns (bool);
}

interface IProofBFailureReporter_2_2 {
    function slashAuctioneerForFailedProofB(
        uint256 sessionId,
        uint256 failedPartyId,
        bool rewardOtherAuctioneer,
        string calldata reason
    ) external returns (uint256 slashAmount, uint256 recipientCount);
}

interface IAuctionResultCommitmentGroth16Verifier_2_2 {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[43] calldata _pubSignals
    ) external view returns (bool);
}


    AuctionResultCommitmentProofRegistry_2_2

    Public-verifiable, commit-then-verify version.

    Important security detail
    Proof B verification also depends on the buyerssellers name arrays because
    those names are used to read canonical bidder commitment records from
    AuctionRegistry. Therefore the committed data must bind
      - proofHash       keccak256(abi.encode(a, b, c, publicSignals))
      - publicInputHash keccak256(abi.encode(publicSignals))
      - bidderListHash  keccak256(abi.encode(buyers, sellers))

    Protocol
      - During Proof phase
          only fixed P0 can commit Proof B hash for targetPartyId = 0.
          only fixed P1 can commit Proof B hash for targetPartyId = 1.

      - During Verify phase
          any public participant can submit the full Proof B.
          contract checks all committed hashes before Groth16 verification.

      - Repeated public verification
          if the same committed proof was already processed, the contract does
          not revert. It emits a repeated-verification event and returns the
          stored result.

contract AuctionResultCommitmentProofRegistry_2_2 {
    address public constant P0_ACCOUNT =
        0xdD2FD4581271e230360230F9337D5c0430Bf44C0;
    address public constant P1_ACCOUNT =
        0xbDA5747bFD65F08deb54cb465eB87D40e51B197E;

    uint256 public constant NB = 2;
    uint256 public constant NS = 2;
    uint256 public constant T = 2;
    uint256 public constant MAX_WINNERS = 1;
    uint256 public constant PUBLIC_SIGNAL_COUNT = 43;

    uint256 private constant SESSION_ID_OFFSET = 0;
    uint256 private constant TARGET_PARTY_ID_OFFSET = 1;
    uint256 private constant K_OFFSET = 2;
    uint256 private constant PB_OFFSET = 3;
    uint256 private constant PS_OFFSET = 4;

    uint256 private constant WINNER_BUYER_START = 5;
    uint256 private constant WINNER_SELLER_START = 6;

    uint256 private constant P0_BUYER_HASH_START = 7;
    uint256 private constant P1_BUYER_HASH_START = 11;
    uint256 private constant P0_SELLER_HASH_START = 15;
    uint256 private constant P1_SELLER_HASH_START = 19;

    uint256 private constant BUYER_COMMIT_START = 23;
    uint256 private constant SELLER_COMMIT_START = 31;

    uint256 private constant BUYER_ID_START = 39;
    uint256 private constant SELLER_ID_START = 41;

    IAuctionRegistryForProofBExact_2_2 public immutable auctionRegistry;
    ICombinedSortingProofRegistryForProofBExact_2_2 public immutable sortingProofRegistry;
    IAuctionResultCommitmentGroth16Verifier_2_2 public immutable verifier;
    IProofBFailureReporter_2_2 public immutable failureReporter;

    address public owner;

    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _reentrancyStatus;

    struct ProofBStatus {
        bool processed;
        bool verified;
        bool failed;
        bool slashed;
        bool proofHashSubmitted;
        address proofCommitter;
        address submitter;  first public verifier that executed verification
        bytes32 committedProofHash;
        bytes32 committedPublicInputHash;
        bytes32 committedBidderListHash;
        bytes32 proofHash;
        bytes32 publicInputHash;
        bytes32 bidderListHash;
        uint256 proofHashSubmittedAtBlock;
        uint256 processedAtBlock;
        uint256 K;
        uint256 Pb;
        uint256 Ps;
        string failureReason;
    }

    mapping(uint256 = mapping(uint256 = ProofBStatus))
        public auctionResultCommitmentProofs;

    event AuctionResultCommitmentProofHashSubmitted(
        uint256 indexed sessionId,
        uint256 indexed targetPartyId,
        address indexed proofCommitter,
        bytes32 proofHash,
        bytes32 publicInputHash,
        bytes32 bidderListHash
    );

    event ProofBVectorHashesChecked(
        uint256 indexed sessionId,
        uint256 indexed targetPartyId,
        address indexed submitter
    );

    event ProofBGroth16Checked(
        uint256 indexed sessionId,
        uint256 indexed targetPartyId,
        address indexed submitter
    );

    event ProofBPostProofPublicInputsChecked(
        uint256 indexed sessionId,
        uint256 indexed targetPartyId,
        address indexed submitter
    );

    event AuctionResultCommitmentProofVerified(
        uint256 indexed sessionId,
        uint256 indexed targetPartyId,
        uint256 K,
        uint256 Pb,
        uint256 Ps,
        address submitter,
        bytes32 proofHash,
        bytes32 publicInputHash,
        bytes32 bidderListHash
    );

    event AuctionResultCommitmentProofRepeatedPublicVerification(
        uint256 indexed sessionId,
        uint256 indexed targetPartyId,
        address indexed verifierCaller,
        bool verified,
        bool failed,
        bytes32 proofHash,
        bytes32 publicInputHash,
        bytes32 bidderListHash
    );

    event AuctionResultCommitmentProofFailedAndSlashed(
        uint256 indexed sessionId,
        uint256 indexed targetPartyId,
        address indexed failedAuctioneer,
        uint256 slashAmount,
        uint256 recipientCount,
        bool rewardOtherAuctioneer,
        string reason
    );

    modifier nonReentrant() {
        require(_reentrancyStatus != _ENTERED, ReentrancyGuard reentrant call);
        _reentrancyStatus = _ENTERED;
        _;
        _reentrancyStatus = _NOT_ENTERED;
    }

    modifier onlyVerifyPhase(uint256 sessionId) {
        require(
            auctionRegistry.isVerifyPhase(sessionId),
            Proof B verification only allowed in Verify phase
        );
        _;
    }

    modifier onlyProofPhase(uint256 sessionId) {
        require(
            auctionRegistry.isProofPhase(sessionId),
            Proof B hash submission only allowed in Proof phase
        );
        _;
    }

    constructor(
        address _auctionRegistry,
        address _sortingProofRegistry,
        address _verifier,
        address _failureReporter
    ) {
        require(_auctionRegistry != address(0), Invalid AuctionRegistry);
        require(_sortingProofRegistry != address(0), Invalid sorting registry);
        require(_verifier != address(0), Invalid verifier);
        require(_failureReporter != address(0), Invalid failure reporter);

        owner = msg.sender;
        auctionRegistry = IAuctionRegistryForProofBExact_2_2(_auctionRegistry);
        sortingProofRegistry =
            ICombinedSortingProofRegistryForProofBExact_2_2(
                _sortingProofRegistry
            );
        verifier = IAuctionResultCommitmentGroth16Verifier_2_2(_verifier);
        failureReporter = IProofBFailureReporter_2_2(_failureReporter);

        _reentrancyStatus = _NOT_ENTERED;
    }

    function submitAuctionResultCommitmentProofHash(
        uint256 sessionId,
        uint256 targetPartyId,
        bytes32 proofHash,
        bytes32 publicInputHash,
        bytes32 bidderListHash
    ) external onlyProofPhase(sessionId) {
        require(targetPartyId == 0  targetPartyId == 1, Invalid targetPartyId);
        require(proofHash != bytes32(0), proof hash is zero);
        require(publicInputHash != bytes32(0), public input hash is zero);
        require(bidderListHash != bytes32(0), bidder list hash is zero);

        _requireCorrectProofHashCommitter(targetPartyId);

        ProofBStatus storage status =
            auctionResultCommitmentProofs[sessionId][targetPartyId];

        require(!status.proofHashSubmitted, Proof B hash already submitted);
        require(!status.processed, Proof B already processed);

        status.proofHashSubmitted = true;
        status.proofCommitter = msg.sender;
        status.committedProofHash = proofHash;
        status.committedPublicInputHash = publicInputHash;
        status.committedBidderListHash = bidderListHash;
        status.proofHashSubmittedAtBlock = block.number;

        emit AuctionResultCommitmentProofHashSubmitted(
            sessionId,
            targetPartyId,
            msg.sender,
            proofHash,
            publicInputHash,
            bidderListHash
        );
    }

    function _requireCorrectProofHashCommitter(uint256 targetPartyId) internal view {
        if (targetPartyId == 0) {
            require(
                msg.sender == P0_ACCOUNT,
                only fixed P0 account can commit Proof B for partyId 0
            );
            require(
                auctionRegistry.p0Auctioneer() == P0_ACCOUNT,
                AuctionRegistry P0 address mismatch
            );
        } else {
            require(
                msg.sender == P1_ACCOUNT,
                only fixed P1 account can commit Proof B for partyId 1
            );
            require(
                auctionRegistry.p1Auctioneer() == P1_ACCOUNT,
                AuctionRegistry P1 address mismatch
            );
        }
    }

    function hasVerifiedAuctionResultCommitmentProof(
        uint256 sessionId,
        uint256 targetPartyId
    ) external view returns (bool) {
        return auctionResultCommitmentProofs[sessionId][targetPartyId].verified;
    }

    function hasProcessedAuctionResultCommitmentProof(
        uint256 sessionId,
        uint256 targetPartyId
    ) external view returns (bool) {
        return auctionResultCommitmentProofs[sessionId][targetPartyId].processed;
    }

    function verifyAuctionResultCommitmentProof(
        string[] calldata buyers,
        string[] calldata sellers,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[43] calldata s
    )
        external
        nonReentrant
        onlyVerifyPhase(s[SESSION_ID_OFFSET])
        returns (bool)
    {
        require(buyers.length == NB, Buyer count mismatch);
        require(sellers.length == NS, Seller count mismatch);

        uint256 sessionId = s[SESSION_ID_OFFSET];
        uint256 targetPartyId = s[TARGET_PARTY_ID_OFFSET];

        require(targetPartyId == 0  targetPartyId == 1, Invalid targetPartyId);

        ProofBStatus storage status =
            auctionResultCommitmentProofs[sessionId][targetPartyId];

        require(status.proofHashSubmitted, Proof B hash not submitted);

        bytes32 proofHash = _proofSubmissionHash(a, b, c, s);
        bytes32 publicInputHash = _publicInputHash(s);
        bytes32 bidderListHash = _bidderListHash(buyers, sellers);

        require(
            proofHash == status.committedProofHash,
            proof data does not match committed Proof B hash
        );
        require(
            publicInputHash == status.committedPublicInputHash,
            public inputs do not match committed Proof B public-input hash
        );
        require(
            bidderListHash == status.committedBidderListHash,
            buyerseller list does not match committed Proof B bidder-list hash
        );

        if (status.processed) {
            require(
                status.proofHash == proofHash,
                Proof B already processed with different proof hash
            );
            require(
                status.publicInputHash == publicInputHash,
                Proof B already processed with different public input hash
            );
            require(
                status.bidderListHash == bidderListHash,
                Proof B already processed with different bidder-list hash
            );

            emit AuctionResultCommitmentProofRepeatedPublicVerification(
                sessionId,
                targetPartyId,
                msg.sender,
                status.verified,
                status.failed,
                proofHash,
                publicInputHash,
                bidderListHash
            );

            return status.verified;
        }

        address expectedSubmitter = _auctioneerAddressByPartyId(targetPartyId);

        require(
            sortingProofRegistry.hasVerifiedCombinedSortingProof(
                sessionId,
                targetPartyId
            ),
            Proof A sorting proof not verified
        );

        status.processed = true;
        status.submitter = msg.sender;
        status.proofHash = proofHash;
        status.publicInputHash = publicInputHash;
        status.bidderListHash = bidderListHash;
        status.processedAtBlock = block.number;
        status.K = s[K_OFFSET];
        status.Pb = s[PB_OFFSET];
        status.Ps = s[PS_OFFSET];

        (bool vectorHashesOk, string memory vectorHashReason) =
            _vectorHashesMatch(sessionId, s);

        if (!vectorHashesOk) {
            return _failAndSlash(
                sessionId,
                targetPartyId,
                expectedSubmitter,
                vectorHashReason
            );
        }

        emit ProofBVectorHashesChecked(sessionId, targetPartyId, msg.sender);

        bool proofOk = verifier.verifyProof(a, b, c, s);

        if (!proofOk) {
            return _failAndSlash(
                sessionId,
                targetPartyId,
                expectedSubmitter,
                Invalid Proof B Groth16 proof
            );
        }

        emit ProofBGroth16Checked(sessionId, targetPartyId, msg.sender);

        (bool postProofInputsOk, string memory postProofReason) =
            _postProofPublicInputsMatch(sessionId, buyers, sellers, s);

        if (!postProofInputsOk) {
            return _failAndSlash(
                sessionId,
                targetPartyId,
                expectedSubmitter,
                postProofReason
            );
        }

        emit ProofBPostProofPublicInputsChecked(
            sessionId,
            targetPartyId,
            msg.sender
        );

        status.verified = true;

        emit AuctionResultCommitmentProofVerified(
            sessionId,
            targetPartyId,
            s[K_OFFSET],
            s[PB_OFFSET],
            s[PS_OFFSET],
            msg.sender,
            proofHash,
            publicInputHash,
            bidderListHash
        );

        return true;
    }

    function _proofSubmissionHash(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[43] calldata s
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(a, b, c, s));
    }

    function _publicInputHash(
        uint256[43] calldata s
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(s));
    }

    function _bidderListHash(
        string[] calldata buyers,
        string[] calldata sellers
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(buyers, sellers));
    }

    function getAuctionResultCommitmentProofCommitment(
        uint256 sessionId,
        uint256 targetPartyId
    )
        external
        view
        returns (
            bool proofHashSubmitted,
            address proofCommitter,
            bytes32 committedProofHash,
            bytes32 committedPublicInputHash,
            bytes32 committedBidderListHash,
            bytes32 verifiedProofHash,
            bytes32 verifiedPublicInputHash,
            bytes32 verifiedBidderListHash,
            uint256 proofHashSubmittedAtBlock
        )
    {
        ProofBStatus memory status =
            auctionResultCommitmentProofs[sessionId][targetPartyId];

        return (
            status.proofHashSubmitted,
            status.proofCommitter,
            status.committedProofHash,
            status.committedPublicInputHash,
            status.committedBidderListHash,
            status.proofHash,
            status.publicInputHash,
            status.bidderListHash,
            status.proofHashSubmittedAtBlock
        );
    }

    function getAuctionResultCommitmentProofStatus(
        uint256 sessionId,
        uint256 targetPartyId
    )
        external
        view
        returns (
            bool processed,
            bool verified,
            bool failed,
            bool slashed,
            bool proofHashSubmitted,
            address proofCommitter,
            address submitter,
            bytes32 proofHash,
            bytes32 publicInputHash,
            bytes32 bidderListHash,
            uint256 processedAtBlock,
            uint256 K,
            uint256 Pb,
            uint256 Ps,
            string memory failureReason
        )
    {
        ProofBStatus memory status =
            auctionResultCommitmentProofs[sessionId][targetPartyId];

        return (
            status.processed,
            status.verified,
            status.failed,
            status.slashed,
            status.proofHashSubmitted,
            status.proofCommitter,
            status.submitter,
            status.proofHash,
            status.publicInputHash,
            status.bidderListHash,
            status.processedAtBlock,
            status.K,
            status.Pb,
            status.Ps,
            status.failureReason
        );
    }

    function _failAndSlash(
        uint256 sessionId,
        uint256 targetPartyId,
        address failedAuctioneer,
        string memory reason
    ) internal returns (bool) {
        ProofBStatus storage status =
            auctionResultCommitmentProofs[sessionId][targetPartyId];

        status.failed = true;
        status.failureReason = reason;

        uint256 otherPartyId = 1 - targetPartyId;

        bool rewardOtherAuctioneer =
            auctionResultCommitmentProofs[sessionId][otherPartyId].verified;

        (
            uint256 slashAmount,
            uint256 recipientCount
        ) = failureReporter.slashAuctioneerForFailedProofB(
                sessionId,
                targetPartyId,
                rewardOtherAuctioneer,
                reason
            );

        status.slashed = slashAmount  0;

        emit AuctionResultCommitmentProofFailedAndSlashed(
            sessionId,
            targetPartyId,
            failedAuctioneer,
            slashAmount,
            recipientCount,
            rewardOtherAuctioneer,
            reason
        );

        return false;
    }

    function _auctioneerAddressByPartyId(
        uint256 partyId
    ) internal view returns (address) {
        if (partyId == 0) {
            return auctionRegistry.p0Auctioneer();
        }

        return auctionRegistry.p1Auctioneer();
    }

    function _vectorHashesMatch(
        uint256 sessionId,
        uint256[43] calldata s
    ) internal view returns (bool ok, string memory reason) {
        (ok, reason) =
            _vectorHashSetMatches(sessionId, 0, 0, P0_BUYER_HASH_START, s);
        if (!ok) return (false, reason);

        (ok, reason) =
            _vectorHashSetMatches(sessionId, 0, 1, P1_BUYER_HASH_START, s);
        if (!ok) return (false, reason);

        (ok, reason) =
            _vectorHashSetMatches(sessionId, 1, 0, P0_SELLER_HASH_START, s);
        if (!ok) return (false, reason);

        (ok, reason) =
            _vectorHashSetMatches(sessionId, 1, 1, P1_SELLER_HASH_START, s);
        if (!ok) return (false, reason);

        return (true, );
    }

    function _postProofPublicInputsMatch(
        uint256 sessionId,
        string[] calldata buyers,
        string[] calldata sellers,
        uint256[43] calldata s
    ) internal view returns (bool ok, string memory reason) {
        for (uint256 i = 0; i  NB; i++) {
            (ok, reason) = _commitmentRecordMatches(
                sessionId,
                buyer,
                buyers[i],
                BUYER_COMMIT_START + i,
                BUYER_COMMIT_START + NB + i,
                BUYER_COMMIT_START + 2  NB + i,
                BUYER_COMMIT_START + 3  NB + i,
                BUYER_ID_START + i,
                s
            );

            if (!ok) return (false, reason);
        }

        for (uint256 j = 0; j  NS; j++) {
            (ok, reason) = _commitmentRecordMatches(
                sessionId,
                seller,
                sellers[j],
                SELLER_COMMIT_START + j,
                SELLER_COMMIT_START + NS + j,
                SELLER_COMMIT_START + 2  NS + j,
                SELLER_COMMIT_START + 3  NS + j,
                SELLER_ID_START + j,
                s
            );

            if (!ok) return (false, reason);
        }

        (ok, reason) = _auctionResultMatches(sessionId, s);
        if (!ok) return (false, reason);

        return (true, );
    }

    function _vectorHashSetMatches(
        uint256 sessionId,
        uint256 datasetKind,
        uint256 partyId,
        uint256 offset,
        uint256[43] calldata s
    ) internal view returns (bool ok, string memory reason) {
        bool exists = auctionRegistry.hasSignedDatasetVectorHashes(
            sessionId,
            datasetKind,
            partyId
        );

        if (!exists) {
            return (
                false,
                _vectorReason(
                    Missing signed vector hashes,
                    datasetKind,
                    partyId
                )
            );
        }

        (
            bool submitted,
            uint256 permutationHash,
            uint256 shareBidVectorHash,
            uint256 randomnessVectorHash,
            uint256 signedMessageHash,

        ) = auctionRegistry.getSignedDatasetVectorHashesFlat(
                sessionId,
                datasetKind,
                partyId
            );

        if (!submitted) {
            return (
                false,
                _vectorReason(
                    Signed vector hashes not submitted,
                    datasetKind,
                    partyId
                )
            );
        }

        if (s[offset] != permutationHash) {
            return (
                false,
                _vectorReason(Permutation hash mismatch, datasetKind, partyId)
            );
        }

        if (s[offset + 1] != shareBidVectorHash) {
            return (
                false,
                _vectorReason(Share-bid hash mismatch, datasetKind, partyId)
            );
        }

        if (s[offset + 2] != randomnessVectorHash) {
            return (
                false,
                _vectorReason(Randomness hash mismatch, datasetKind, partyId)
            );
        }

        if (s[offset + 3] != signedMessageHash) {
            return (
                false,
                _vectorReason(
                    Signed message hash mismatch,
                    datasetKind,
                    partyId
                )
            );
        }

        return (true, );
    }

    function _commitmentRecordMatches(
        uint256 sessionId,
        string memory role,
        string calldata name,
        uint256 c0xOffset,
        uint256 c0yOffset,
        uint256 c1xOffset,
        uint256 c1yOffset,
        uint256 idOffset,
        uint256[43] calldata s
    ) internal view returns (bool ok, string memory reason) {
        (
            bool submitted,
            ,
            ,
            uint256 bidderId,
            ,
            uint256 c0x,
            uint256 c0y,
            uint256 c1x,
            uint256 c1y,

        ) = auctionRegistry.getBidderShareCommitmentsFlat(
                sessionId,
                role,
                name
            );

        if (!submitted) return (false, Commitment not submitted);
        if (s[idOffset] != bidderId) return (false, Bidder ID mismatch);
        if (s[c0xOffset] != c0x) return (false, c0.x mismatch);
        if (s[c0yOffset] != c0y) return (false, c0.y mismatch);
        if (s[c1xOffset] != c1x) return (false, c1.x mismatch);
        if (s[c1yOffset] != c1y) return (false, c1.y mismatch);

        return (true, );
    }

    function _auctionResultMatches(
        uint256 sessionId,
        uint256[43] calldata s
    ) internal view returns (bool ok, string memory reason) {
        bool resultsMatch = auctionRegistry.auctionResultsMatch(sessionId);

        if (!resultsMatch) {
            return (false, P0P1 auction results do not match);
        }

        (
            bool submitted,
            uint256 K,
            uint256 Pb,
            uint256 Ps,
            uint256[] memory winnerBuyerIds,
            uint256[] memory winnerSellerIds,
            ,
            ,

        ) = auctionRegistry.getAuctionResultFlat(sessionId, 0);

        if (!submitted) return (false, P0 auction result not submitted);
        if (s[K_OFFSET] != K) return (false, K mismatch);
        if (s[PB_OFFSET] != Pb) return (false, Pb mismatch);
        if (s[PS_OFFSET] != Ps) return (false, Ps mismatch);

        uint256 expectedWinnerCount = K == 0  0  K - 1;

        if (expectedWinnerCount  MAX_WINNERS) {
            return (false, Winner count exceeds MAX_WINNERS);
        }

        if (winnerBuyerIds.length != expectedWinnerCount) {
            return (false, Winner buyer count mismatch);
        }

        if (winnerSellerIds.length != expectedWinnerCount) {
            return (false, Winner seller count mismatch);
        }

        for (uint256 i = 0; i  MAX_WINNERS; i++) {
            uint256 buyerSignal = s[WINNER_BUYER_START + i];
            uint256 sellerSignal = s[WINNER_SELLER_START + i];

            if (i  expectedWinnerCount) {
                if (buyerSignal != winnerBuyerIds[i]) {
                    return (false, Winner buyer ID mismatch);
                }

                if (sellerSignal != winnerSellerIds[i]) {
                    return (false, Winner seller ID mismatch);
                }
            } else {
                if (buyerSignal != 0) {
                    return (false, Trailing winner buyer ID must be zero);
                }

                if (sellerSignal != 0) {
                    return (false, Trailing winner seller ID must be zero);
                }
            }
        }

        return (true, );
    }

    function _vectorReason(
        string memory base,
        uint256 datasetKind,
        uint256 partyId
    ) internal pure returns (string memory) {
        return string(
            abi.encodePacked(
                base,
                 datasetKind=,
                _uintToString(datasetKind),
                 partyId=,
                _uintToString(partyId)
            )
        );
    }

    function _uintToString(
        uint256 value
    ) internal pure returns (string memory) {
        if (value == 0) {
            return 0;
        }

        uint256 temp = value;
        uint256 digits;

        while (temp != 0) {
            digits++;
            temp = 10;
        }

        bytes memory buffer = new bytes(digits);

        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value = 10;
        }

        return string(buffer);
    }
}
