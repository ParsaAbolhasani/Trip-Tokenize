// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

interface IRWAVotesToken {
    function getPastVotes(address account, uint256 timepoint) external view returns (uint256);
    function getPastTotalSupply(uint256 timepoint) external view returns (uint256);
}

/**
 * @title EmergencyGovernanceHook
 * @author Parsa Abolhasani Rad (Aervynx Ecosystem)
 * @notice UUPS upgradeable snapshot-based governance hook for total-loss settlement,
 *         operator replacement, and emergency protocol interventions using ERC20Votes checkpoints.
 */
contract EmergencyGovernanceHook is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    uint256 public constant BPS_DENOMINATOR = 10_000;

    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    enum ProposalType {
        TOTAL_LOSS_SETTLEMENT,
        OPERATOR_REPLACEMENT,
        EMERGENCY_PAUSE,
        PARAMETER_OVERRIDE
    }

    enum ProposalStatus {
        ACTIVE,
        REJECTED,
        EXECUTED,
        CANCELLED
    }

    struct Proposal {
        uint256 id;
        ProposalType proposalType;
        bytes32 assetId;
        address proposer;
        address target;
        bytes callData;
        bytes32 evidenceHash;
        uint256 snapshotBlock;
        uint256 startTime;
        uint256 endTime;
        uint256 forVotes;
        uint256 againstVotes;
        ProposalStatus status;
    }

    uint256 private _reentrancyStatus;

    IRWAVotesToken public votingToken;

    uint256 public votingPeriod;
    uint256 public quorumBps;
    uint256 public minProposerWeightBps;
    uint256 public nextProposalId;

    mapping(address => bool) public approvedTargets;
    mapping(uint256 => Proposal) private _proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    event TargetApproved(address indexed target, bool status);
    event ProposalCreated(
        uint256 indexed proposalId,
        ProposalType proposalType,
        bytes32 indexed assetId,
        address indexed proposer,
        uint256 snapshotBlock,
        uint256 endTime
    );
    event VoteCast(uint256 indexed proposalId, address indexed voter, bool support, uint256 weight);
    event ProposalExecuted(uint256 indexed proposalId, address indexed executor);
    event ProposalRejected(uint256 indexed proposalId);
    event ProposalCancelled(uint256 indexed proposalId, address indexed guardian);
    event GovernanceConfigUpdated(
        uint256 votingPeriod,
        uint256 quorumBps,
        uint256 minProposerWeightBps
    );

    error InvalidAddress();
    error InvalidEvidenceHash();
    error TargetNotApproved(address target);
    error InvalidGovernanceConfig();
    error ZeroSnapshotSupply();
    error InsufficientVotingPower(uint256 requiredWeight, uint256 actualWeight);
    error ProposalNotFound(uint256 proposalId);
    error ProposalNotActive(ProposalStatus status);
    error VotingEnded(uint256 endTime);
    error VotingStillActive(uint256 endTime);
    error AlreadyVoted(uint256 proposalId, address voter);
    error ProposalExecutionFailed();
    error ReentrantCall();

    modifier nonReentrant() {
        if (_reentrancyStatus == _ENTERED) revert ReentrantCall();
        _reentrancyStatus = _ENTERED;
        _;
        _reentrancyStatus = _NOT_ENTERED;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes governance with VehicleRWARegistry (ERC20Votes) and default 48h / 20% quorum settings.
     */
    function initialize(address _votingToken, address admin) public initializer {
        if (_votingToken == address(0) || admin == address(0)) revert InvalidAddress();

        __AccessControl_init();
        __Pausable_init();

        _reentrancyStatus = _NOT_ENTERED;
        votingToken = IRWAVotesToken(_votingToken);
        votingPeriod = 48 hours;
        quorumBps = 2000;
        minProposerWeightBps = 100;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    function setApprovedTarget(address target, bool status) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (target == address(0)) revert InvalidAddress();
        approvedTargets[target] = status;
        emit TargetApproved(target, status);
    }

    function setGovernanceConfig(
        uint256 _votingPeriod,
        uint256 _quorumBps,
        uint256 _minProposerWeightBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (
            _votingPeriod < 1 hours ||
            _votingPeriod > 14 days ||
            _quorumBps < 500 ||
            _quorumBps > 8000 ||
            _minProposerWeightBps > 2000
        ) revert InvalidGovernanceConfig();

        votingPeriod = _votingPeriod;
        quorumBps = _quorumBps;
        minProposerWeightBps = _minProposerWeightBps;

        emit GovernanceConfigUpdated(_votingPeriod, _quorumBps, _minProposerWeightBps);
    }

    /**
     * @notice Creates a proposal anchored to the previous block snapshot to prevent double-voting via transfers.
     * @dev Token holders must call delegate(self) on VehicleRWARegistry prior to snapshotBlock to activate voting power.
     */
    function createProposal(
        ProposalType proposalType,
        bytes32 assetId,
        address target,
        bytes calldata callData,
        bytes32 evidenceHash
    ) external whenNotPaused returns (uint256 proposalId) {
        if (evidenceHash == bytes32(0)) revert InvalidEvidenceHash();
        if (target != address(0) && !approvedTargets[target]) revert TargetNotApproved(target);

        uint256 snapBlock = block.number > 0 ? block.number - 1 : 0;

        if (!hasRole(GUARDIAN_ROLE, msg.sender)) {
            uint256 pastSupply = votingToken.getPastTotalSupply(snapBlock);
            if (pastSupply == 0) revert ZeroSnapshotSupply();

            uint256 minWeight = (pastSupply * minProposerWeightBps) / BPS_DENOMINATOR;
            uint256 proposerWeight = votingToken.getPastVotes(msg.sender, snapBlock);
            if (proposerWeight < minWeight) {
                revert InsufficientVotingPower(minWeight, proposerWeight);
            }
        }

        proposalId = ++nextProposalId;
        uint256 endTime = block.timestamp + votingPeriod;

        Proposal storage p = _proposals[proposalId];
        p.id = proposalId;
        p.proposalType = proposalType;
        p.assetId = assetId;
        p.proposer = msg.sender;
        p.target = target;
        p.callData = callData;
        p.evidenceHash = evidenceHash;
        p.snapshotBlock = snapBlock;
        p.startTime = block.timestamp;
        p.endTime = endTime;
        p.status = ProposalStatus.ACTIVE;

        emit ProposalCreated(proposalId, proposalType, assetId, msg.sender, snapBlock, endTime);
    }

    function castVote(uint256 proposalId, bool support) external whenNotPaused {
        Proposal storage p = _proposals[proposalId];
        if (p.id == 0) revert ProposalNotFound(proposalId);
        if (p.status != ProposalStatus.ACTIVE) revert ProposalNotActive(p.status);
        if (block.timestamp > p.endTime) revert VotingEnded(p.endTime);
        if (hasVoted[proposalId][msg.sender]) revert AlreadyVoted(proposalId, msg.sender);

        uint256 weight = votingToken.getPastVotes(msg.sender, p.snapshotBlock);
        if (weight == 0) revert InsufficientVotingPower(1, 0);

        hasVoted[proposalId][msg.sender] = true;
        if (support) {
            p.forVotes += weight;
        } else {
            p.againstVotes += weight;
        }

        emit VoteCast(proposalId, msg.sender, support, weight);
    }

    function executeProposal(uint256 proposalId) external whenNotPaused nonReentrant {
        Proposal storage p = _proposals[proposalId];
        if (p.id == 0) revert ProposalNotFound(proposalId);
        if (p.status != ProposalStatus.ACTIVE) revert ProposalNotActive(p.status);
        if (block.timestamp <= p.endTime) revert VotingStillActive(p.endTime);

        uint256 pastSupply = votingToken.getPastTotalSupply(p.snapshotBlock);
        uint256 requiredQuorum = (pastSupply * quorumBps) / BPS_DENOMINATOR;
        uint256 totalParticipation = p.forVotes + p.againstVotes;

        if (pastSupply == 0 || totalParticipation < requiredQuorum || p.forVotes <= p.againstVotes) {
            p.status = ProposalStatus.REJECTED;
            emit ProposalRejected(proposalId);
            return;
        }

        p.status = ProposalStatus.EXECUTED;

        if (p.target != address(0) && p.callData.length > 0) {
            if (!approvedTargets[p.target]) revert TargetNotApproved(p.target);
            (bool success, ) = p.target.call(p.callData);
            if (!success) revert ProposalExecutionFailed();
        }

        emit ProposalExecuted(proposalId, msg.sender);
    }

    function cancelProposal(uint256 proposalId) external onlyRole(GUARDIAN_ROLE) {
        Proposal storage p = _proposals[proposalId];
        if (p.id == 0) revert ProposalNotFound(proposalId);
        if (p.status != ProposalStatus.ACTIVE) revert ProposalNotActive(p.status);

        p.status = ProposalStatus.CANCELLED;
        emit ProposalCancelled(proposalId, msg.sender);
    }

    function getProposal(uint256 proposalId) external view returns (Proposal memory) {
        if (_proposals[proposalId].id == 0) revert ProposalNotFound(proposalId);
        return _proposals[proposalId];
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}

    uint256[40] private __gap;
}
