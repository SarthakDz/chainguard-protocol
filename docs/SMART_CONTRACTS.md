# 📜 ChainGuard Protocol — Smart Contract Specifications

## Overview

ChainGuard deploys **4 smart contracts** that form the decentralized backbone
of the threat intelligence and governance system.

| Contract | Purpose | Network |
|---|---|---|
| `ThreatRegistry.sol` | Decentralized malware blacklist oracle | ETH + Polygon |
| `ReputationOracle.sol` | Address reputation scoring | ETH + Polygon |
| `IncidentVault.sol` | Forensic evidence preservation | Polygon (low gas) |
| `GovernanceDAO.sol` | Protocol governance + dispute resolution | ETH |

---

## Contract 1: ThreatRegistry.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title ThreatRegistry
 * @notice Decentralized, immutable blacklist of malicious blockchain addresses,
 *         transaction hashes, and contract addresses. The heart of ChainGuard's
 *         on-chain threat intelligence system.
 * @dev Multi-sig write access, public read, governed by ChainGuardDAO
 */
contract ThreatRegistry is AccessControl, ReentrancyGuard, Pausable {
    
    // === ROLES ===
    bytes32 public constant REPORTER_ROLE = keccak256("REPORTER_ROLE");
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");
    
    // === ENUMS ===
    enum Severity { LOW, MEDIUM, HIGH, CRITICAL }
    enum ThreatType { 
        RANSOMWARE_C2, 
        WALLET_DRAINER, 
        PHISHING, 
        MONEY_LAUNDERING,
        EXPLOIT_CONTRACT,
        CREDENTIAL_STEALER,
        SANCTIONED,
        UNKNOWN 
    }
    enum Status { PENDING, CONFIRMED, DISPUTED, REMOVED }
    
    // === STRUCTS ===
    struct ThreatRecord {
        address reporter;           // Who reported this
        uint256 timestamp;          // When first reported
        Severity severity;          // Threat severity
        ThreatType threatType;      // Type of threat
        Status status;              // Current status
        bytes32 evidenceHash;       // IPFS CID of evidence (keccak256)
        string evidenceIpfsCid;     // IPFS CID string
        uint16 confirmations;       // How many validators confirmed
        uint16 disputes;            // How many disputes raised
        string malwareFamily;       // e.g., "locky_v4", "metamask_drainer_v2"
        uint256 lastUpdated;
    }
    
    // === STATE ===
    // Malicious EOA/Contract addresses
    mapping(address => ThreatRecord) public addressThreats;
    address[] public blacklistedAddresses;
    
    // Malicious transaction hashes
    mapping(bytes32 => ThreatRecord) public txHashThreats;
    bytes32[] public blacklistedTxHashes;
    
    // Pending reports (before confirmation)
    mapping(bytes32 => ThreatRecord) public pendingReports;
    
    // Validation tracking
    mapping(bytes32 => mapping(address => bool)) public validatorVotes;
    uint256 public constant MIN_CONFIRMATIONS = 3;
    
    // === EVENTS ===
    event ThreatReported(
        address indexed indicator, 
        Severity severity, 
        ThreatType threatType,
        address indexed reporter
    );
    event ThreatConfirmed(
        address indexed indicator,
        uint16 confirmations,
        address indexed validator
    );
    event ThreatDisputed(
        address indexed indicator,
        address indexed disputer,
        string reason
    );
    event ThreatRemoved(
        address indexed indicator,
        address indexed remover,
        string reason
    );
    event TxHashBlacklisted(
        bytes32 indexed txHash,
        Severity severity,
        string malwareFamily
    );
    
    // === CONSTRUCTOR ===
    constructor(address[] memory initialValidators) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GOVERNANCE_ROLE, msg.sender);
        
        for (uint i = 0; i < initialValidators.length; i++) {
            _grantRole(VALIDATOR_ROLE, initialValidators[i]);
            _grantRole(REPORTER_ROLE, initialValidators[i]);
        }
    }
    
    // === WRITE FUNCTIONS ===
    
    /**
     * @notice Report a malicious address
     * @param indicator The malicious address
     * @param severity Threat severity level
     * @param threatType Type of threat
     * @param evidenceIpfsCid IPFS CID containing evidence
     * @param malwareFamily Malware family name
     */
    function reportAddressThreat(
        address indicator,
        Severity severity,
        ThreatType threatType,
        string calldata evidenceIpfsCid,
        string calldata malwareFamily
    ) external onlyRole(REPORTER_ROLE) whenNotPaused {
        require(indicator != address(0), "Invalid address");
        require(addressThreats[indicator].timestamp == 0, "Already reported");
        
        addressThreats[indicator] = ThreatRecord({
            reporter: msg.sender,
            timestamp: block.timestamp,
            severity: severity,
            threatType: threatType,
            status: Status.PENDING,
            evidenceHash: keccak256(bytes(evidenceIpfsCid)),
            evidenceIpfsCid: evidenceIpfsCid,
            confirmations: 1,
            disputes: 0,
            malwareFamily: malwareFamily,
            lastUpdated: block.timestamp
        });
        
        blacklistedAddresses.push(indicator);
        
        emit ThreatReported(indicator, severity, threatType, msg.sender);
        
        // Auto-confirm CRITICAL threats from trusted reporters
        if (severity == Severity.CRITICAL) {
            _autoConfirmCritical(indicator);
        }
    }
    
    /**
     * @notice Validate/confirm a reported threat
     * @param indicator Address to confirm as malicious
     */
    function confirmThreat(address indicator) 
        external 
        onlyRole(VALIDATOR_ROLE) 
        whenNotPaused 
    {
        ThreatRecord storage record = addressThreats[indicator];
        require(record.timestamp != 0, "Not reported");
        require(!validatorVotes[bytes32(uint256(uint160(indicator)))][msg.sender], "Already voted");
        
        validatorVotes[bytes32(uint256(uint160(indicator)))][msg.sender] = true;
        record.confirmations++;
        record.lastUpdated = block.timestamp;
        
        if (record.confirmations >= MIN_CONFIRMATIONS) {
            record.status = Status.CONFIRMED;
        }
        
        emit ThreatConfirmed(indicator, record.confirmations, msg.sender);
    }
    
    /**
     * @notice Report a malicious transaction hash (blockchain-hosted payload)
     */
    function reportTxHashThreat(
        bytes32 txHash,
        Severity severity,
        ThreatType threatType,
        string calldata evidenceIpfsCid,
        string calldata malwareFamily
    ) external onlyRole(REPORTER_ROLE) whenNotPaused {
        require(txHashThreats[txHash].timestamp == 0, "Already reported");
        
        txHashThreats[txHash] = ThreatRecord({
            reporter: msg.sender,
            timestamp: block.timestamp,
            severity: severity,
            threatType: threatType,
            status: severity == Severity.CRITICAL ? Status.CONFIRMED : Status.PENDING,
            evidenceHash: keccak256(bytes(evidenceIpfsCid)),
            evidenceIpfsCid: evidenceIpfsCid,
            confirmations: 1,
            disputes: 0,
            malwareFamily: malwareFamily,
            lastUpdated: block.timestamp
        });
        
        blacklistedTxHashes.push(txHash);
        
        emit TxHashBlacklisted(txHash, severity, malwareFamily);
    }
    
    // === READ FUNCTIONS ===
    
    /**
     * @notice Check if an address is blacklisted
     * @return isBlacklisted Whether the address is confirmed malicious
     * @return record The full threat record if exists
     */
    function checkAddress(address indicator) 
        external 
        view 
        returns (bool isBlacklisted, ThreatRecord memory record) 
    {
        record = addressThreats[indicator];
        isBlacklisted = record.status == Status.CONFIRMED;
    }
    
    /**
     * @notice Check if a transaction hash contains malicious payload
     */
    function checkTxHash(bytes32 txHash)
        external
        view
        returns (bool isMalicious, ThreatRecord memory record)
    {
        record = txHashThreats[txHash];
        isMalicious = record.status == Status.CONFIRMED;
    }
    
    /**
     * @notice Batch check multiple addresses (gas-efficient for extension use)
     */
    function batchCheckAddresses(address[] calldata indicators)
        external
        view
        returns (bool[] memory results)
    {
        results = new bool[](indicators.length);
        for (uint i = 0; i < indicators.length; i++) {
            results[i] = addressThreats[indicators[i]].status == Status.CONFIRMED;
        }
    }
    
    /**
     * @notice Get total blacklisted address count
     */
    function getBlacklistSize() external view returns (uint256) {
        return blacklistedAddresses.length;
    }
    
    // === INTERNAL ===
    
    function _autoConfirmCritical(address indicator) internal {
        ThreatRecord storage record = addressThreats[indicator];
        record.status = Status.CONFIRMED;
        record.confirmations = uint16(MIN_CONFIRMATIONS);
        emit ThreatConfirmed(indicator, record.confirmations, msg.sender);
    }
    
    // === GOVERNANCE ===
    
    function removeFromBlacklist(address indicator, string calldata reason)
        external
        onlyRole(GOVERNANCE_ROLE)
    {
        addressThreats[indicator].status = Status.REMOVED;
        emit ThreatRemoved(indicator, msg.sender, reason);
    }
    
    function pause() external onlyRole(GOVERNANCE_ROLE) { _pause(); }
    function unpause() external onlyRole(GOVERNANCE_ROLE) { _unpause(); }
}
```

---

## Contract 2: ReputationOracle.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ReputationOracle
 * @notice Provides on-chain reputation scores for Ethereum addresses.
 *         Scores are calculated off-chain and submitted by trusted keeper network.
 *         Range: 0 (worst) to 100 (best)
 */
contract ReputationOracle is Ownable {
    
    struct ReputationScore {
        uint8 score;            // 0-100
        uint8 confidence;       // 0-100 (how confident we are)
        uint256 lastUpdated;
        string riskCategory;    // BLACKLISTED/HIGH_RISK/SUSPICIOUS/NEUTRAL/TRUSTED
        bytes32 dataHash;       // Hash of off-chain calculation inputs
    }
    
    mapping(address => ReputationScore) public scores;
    mapping(address => bool) public authorizedUpdaters;
    
    uint256 public constant SCORE_TTL = 1 hours;
    uint256 public constant DEFAULT_SCORE = 50; // Neutral for unknown addresses
    
    event ScoreUpdated(
        address indexed subject, 
        uint8 newScore, 
        string riskCategory,
        address indexed updater
    );
    
    modifier onlyAuthorized() {
        require(authorizedUpdaters[msg.sender], "Not authorized");
        _;
    }
    
    constructor() Ownable(msg.sender) {
        authorizedUpdaters[msg.sender] = true;
    }
    
    /**
     * @notice Update reputation score for an address
     */
    function updateScore(
        address subject,
        uint8 score,
        uint8 confidence,
        string calldata riskCategory,
        bytes32 dataHash
    ) external onlyAuthorized {
        scores[subject] = ReputationScore({
            score: score,
            confidence: confidence,
            lastUpdated: block.timestamp,
            riskCategory: riskCategory,
            dataHash: dataHash
        });
        
        emit ScoreUpdated(subject, score, riskCategory, msg.sender);
    }
    
    /**
     * @notice Batch update scores (gas-efficient for keeper network)
     */
    function batchUpdateScores(
        address[] calldata subjects,
        uint8[] calldata scoreValues,
        string[] calldata categories
    ) external onlyAuthorized {
        require(subjects.length == scoreValues.length, "Length mismatch");
        
        for (uint i = 0; i < subjects.length; i++) {
            scores[subjects[i]].score = scoreValues[i];
            scores[subjects[i]].riskCategory = categories[i];
            scores[subjects[i]].lastUpdated = block.timestamp;
            
            emit ScoreUpdated(subjects[i], scoreValues[i], categories[i], msg.sender);
        }
    }
    
    /**
     * @notice Get reputation score, returns default if unknown
     */
    function getScore(address subject) 
        external 
        view 
        returns (uint8 score, string memory category, bool isFresh) 
    {
        ReputationScore memory rep = scores[subject];
        
        if (rep.lastUpdated == 0) {
            return (uint8(DEFAULT_SCORE), "NEUTRAL", false);
        }
        
        isFresh = (block.timestamp - rep.lastUpdated) < SCORE_TTL;
        return (rep.score, rep.riskCategory, isFresh);
    }
    
    /**
     * @notice Batch get scores (gas-efficient reads)
     */
    function batchGetScores(address[] calldata subjects)
        external
        view
        returns (uint8[] memory scoreValues)
    {
        scoreValues = new uint8[](subjects.length);
        for (uint i = 0; i < subjects.length; i++) {
            ReputationScore memory rep = scores[subjects[i]];
            scoreValues[i] = rep.lastUpdated == 0 ? uint8(DEFAULT_SCORE) : rep.score;
        }
    }
    
    function setAuthorizedUpdater(address updater, bool status) external onlyOwner {
        authorizedUpdaters[updater] = status;
    }
}
```

---

## Contract 3: IncidentVault.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IncidentVault
 * @notice Immutable storage of cryptographic proofs for ChainGuard incidents.
 *         Evidence hashes stored here provide legally admissible proof of attacks.
 *         Deployed on Polygon for low-cost, high-frequency writes.
 */
contract IncidentVault {
    
    struct Incident {
        string incidentId;          // INC_timestamp_random
        address victim;             // Victim address (optional, can be zero)
        address maliciousActor;     // Confirmed malicious address
        string threatType;          // Threat classification
        string evidenceIpfsCid;     // IPFS CID of full evidence bundle
        bytes32 evidenceHash;       // keccak256 of evidence for verification
        uint256 timestamp;
        address reporter;           // ChainGuard agent address
        string malwareFamily;
        uint8 severity;             // 1-4
    }
    
    Incident[] public incidents;
    mapping(string => uint256) public incidentIdToIndex;
    mapping(address => uint256[]) public incidentsByActor;
    mapping(address => uint256[]) public incidentsByVictim;
    
    event IncidentRecorded(
        string indexed incidentId,
        address indexed maliciousActor,
        string threatType,
        string evidenceIpfsCid
    );
    
    address public immutable chainguardSentinel;
    
    modifier onlySentinel() {
        require(msg.sender == chainguardSentinel, "Only ChainGuard Sentinel");
        _;
    }
    
    constructor(address _sentinel) {
        chainguardSentinel = _sentinel;
    }
    
    function recordIncident(
        string calldata incidentId,
        address victim,
        address maliciousActor,
        string calldata threatType,
        string calldata evidenceIpfsCid,
        string calldata malwareFamily,
        uint8 severity
    ) external onlySentinel returns (uint256 incidentIndex) {
        
        incidentIndex = incidents.length;
        
        incidents.push(Incident({
            incidentId: incidentId,
            victim: victim,
            maliciousActor: maliciousActor,
            threatType: threatType,
            evidenceIpfsCid: evidenceIpfsCid,
            evidenceHash: keccak256(bytes(evidenceIpfsCid)),
            timestamp: block.timestamp,
            reporter: msg.sender,
            malwareFamily: malwareFamily,
            severity: severity
        }));
        
        incidentIdToIndex[incidentId] = incidentIndex;
        if (maliciousActor != address(0)) {
            incidentsByActor[maliciousActor].push(incidentIndex);
        }
        if (victim != address(0)) {
            incidentsByVictim[victim].push(incidentIndex);
        }
        
        emit IncidentRecorded(incidentId, maliciousActor, threatType, evidenceIpfsCid);
    }
    
    function getIncidentsByActor(address actor) 
        external view returns (Incident[] memory actorIncidents) 
    {
        uint256[] memory indices = incidentsByActor[actor];
        actorIncidents = new Incident[](indices.length);
        for (uint i = 0; i < indices.length; i++) {
            actorIncidents[i] = incidents[indices[i]];
        }
    }
    
    function getTotalIncidents() external view returns (uint256) {
        return incidents.length;
    }
}
```

---

## Contract 4: GovernanceDAO.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";

/**
 * @title ChainGuardDAO
 * @notice Governance contract for ChainGuard Protocol.
 *         Handles: false positive disputes, protocol upgrades,
 *         new validator approvals, fee parameter changes.
 * @dev Uses OpenZeppelin Governor framework with CGT (ChainGuard Token) voting
 */
contract ChainGuardDAO is
    Governor,
    GovernorSettings,
    GovernorCountingSimple,
    GovernorVotes,
    GovernorVotesQuorumFraction
{
    constructor(IVotes _token)
        Governor("ChainGuardDAO")
        GovernorSettings(
            1 days,      // voting delay
            1 weeks,     // voting period
            1000e18      // proposal threshold (1000 CGT)
        )
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(10) // 10% quorum
    {}

    // Required overrides
    function votingDelay() public view override(Governor, GovernorSettings)
        returns (uint256) { return super.votingDelay(); }
    
    function votingPeriod() public view override(Governor, GovernorSettings)
        returns (uint256) { return super.votingPeriod(); }
    
    function quorum(uint256 blockNumber)
        public view override(Governor, GovernorVotesQuorumFraction)
        returns (uint256) { return super.quorum(blockNumber); }
    
    function proposalThreshold()
        public view override(Governor, GovernorSettings)
        returns (uint256) { return super.proposalThreshold(); }
}
```

---

## Deployment Configuration

```javascript
// scripts/deploy.js
const hre = require("hardhat");

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    
    console.log("Deploying ChainGuard contracts...");
    console.log("Deployer:", deployer.address);
    
    // Initial validators (ChainGuard trusted security orgs)
    const validators = [
        "0x...", // ChainGuard Labs
        "0x...", // CertiK
        "0x...", // OpenZeppelin
        "0x...", // Trail of Bits
        "0x...", // Consensys Diligence
    ];
    
    // Deploy ThreatRegistry
    const ThreatRegistry = await hre.ethers.getContractFactory("ThreatRegistry");
    const threatRegistry = await ThreatRegistry.deploy(validators);
    await threatRegistry.waitForDeployment();
    console.log("ThreatRegistry:", await threatRegistry.getAddress());
    
    // Deploy ReputationOracle
    const ReputationOracle = await hre.ethers.getContractFactory("ReputationOracle");
    const reputationOracle = await ReputationOracle.deploy();
    await reputationOracle.waitForDeployment();
    console.log("ReputationOracle:", await reputationOracle.getAddress());
    
    // Deploy IncidentVault (on Polygon)
    const IncidentVault = await hre.ethers.getContractFactory("IncidentVault");
    const incidentVault = await IncidentVault.deploy(deployer.address); // sentinel addr
    await incidentVault.waitForDeployment();
    console.log("IncidentVault:", await incidentVault.getAddress());
    
    // Verify on Etherscan
    if (hre.network.name !== "localhost" && hre.network.name !== "hardhat") {
        await hre.run("verify:verify", {
            address: await threatRegistry.getAddress(),
            constructorArguments: [validators],
        });
    }
    
    console.log("\n✅ All ChainGuard contracts deployed successfully!");
}

main().catch(console.error);
```

---

## Contract Addresses (Testnet)

```yaml
sepolia:
  ThreatRegistry: "0x..."
  ReputationOracle: "0x..."
  IncidentVault: "0x..."
  GovernanceDAO: "0x..."
  
polygon_amoy:
  ThreatRegistry: "0x..."
  ReputationOracle: "0x..."
  IncidentVault: "0x..."
```
