// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title AutomatedTaxAndAuditLedger
 * @author Parsa Abolhasani Rad (Aervynx Ecosystem)
 * @notice UUPS upgradeable, append-only on-chain tax, depreciation, and regulatory audit ledger
 *         designed to compile without stack-too-deep issues.
 */
contract AutomatedTaxAndAuditLedger is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    bytes32 public constant ACCOUNTANT_ROLE = keccak256("ACCOUNTANT_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant MAX_TAX_RATE_BPS = 5000;

    struct EntryInput {
        bytes32 periodId;
        bytes32 assetId;
        uint256 grossRevenue;
        uint256 deductibleOpex;
        uint256 depreciationAmount;
        uint256 reserveAllocation;
        uint256 investorDistribution;
        uint256 operatorDistribution;
        bytes32 auditDocHash;
    }

    struct LedgerEntry {
        uint256 entryId;
        bytes32 periodId;
        bytes32 assetId;
        uint256 grossRevenue;
        uint256 deductibleOpex;
        uint256 depreciationAmount;
        uint256 reserveAllocation;
        uint256 investorDistribution;
        uint256 operatorDistribution;
        uint256 taxableIncome;
        uint256 estimatedTax;
        bytes32 auditDocHash;
        uint256 recordedAt;
        address recordedBy;
    }

    struct AuditAdjustment {
        uint256 adjustmentId;
        uint256 originalEntryId;
        int256 taxableIncomeDelta;
        int256 taxDelta;
        bytes32 justificationHash;
        uint256 recordedAt;
        address recordedBy;
    }

    uint256 public taxRateBps;
    uint256 public nextEntryId;
    uint256 public nextAdjustmentId;

    uint256 public totalGrossRevenue;
    uint256 public totalDeductibleOpex;
    uint256 public totalDepreciation;
    uint256 public totalTaxableIncome;
    uint256 public totalEstimatedTax;

    mapping(uint256 => LedgerEntry) private _entries;
    mapping(uint256 => AuditAdjustment) private _adjustments;
    mapping(bytes32 => uint256) public entryIdByPeriodAndAsset;
    mapping(bytes32 => uint256) public accumulatedDepreciationByAsset;

    event LedgerEntryRecorded(
        uint256 indexed entryId,
        bytes32 indexed periodId,
        bytes32 indexed assetId,
        uint256 taxableIncome,
        uint256 estimatedTax,
        bytes32 auditDocHash
    );
    event AuditAdjustmentRecorded(
        uint256 indexed adjustmentId,
        uint256 indexed originalEntryId,
        int256 taxableIncomeDelta,
        int256 taxDelta,
        bytes32 justificationHash
    );
    event TaxRateUpdated(uint256 oldRateBps, uint256 newRateBps);

    error InvalidAddress();
    error InvalidTaxRate(uint256 rateBps);
    error InvalidPeriodId();
    error InvalidDocumentHash();
    error EntryAlreadyExists(bytes32 periodId, bytes32 assetId);
    error EntryNotFound(uint256 entryId);
    error AdjustmentNotFound(uint256 adjustmentId);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the immutable audit ledger with corporate tax rate in basis points.
     */
    function initialize(address admin, uint256 _taxRateBps) public initializer {
        if (admin == address(0)) revert InvalidAddress();
        if (_taxRateBps > MAX_TAX_RATE_BPS) revert InvalidTaxRate(_taxRateBps);

        __AccessControl_init();
        __Pausable_init();

        taxRateBps = _taxRateBps;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ACCOUNTANT_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    function recordPeriodEntry(EntryInput calldata input)
        external
        onlyRole(ACCOUNTANT_ROLE)
        whenNotPaused
        returns (uint256 entryId)
    {
        if (input.periodId == bytes32(0)) revert InvalidPeriodId();
        if (input.auditDocHash == bytes32(0)) revert InvalidDocumentHash();

        bytes32 compositeKey = keccak256(abi.encodePacked(input.periodId, input.assetId));
        if (entryIdByPeriodAndAsset[compositeKey] != 0) {
            revert EntryAlreadyExists(input.periodId, input.assetId);
        }

        entryId = ++nextEntryId;
        entryIdByPeriodAndAsset[compositeKey] = entryId;

        (uint256 taxable, uint256 estTax) = _calculateTax(
            input.grossRevenue,
            input.deductibleOpex,
            input.depreciationAmount
        );

        _storeEntry(entryId, input, taxable, estTax);
        _updateTotals(input, taxable, estTax);

        emit LedgerEntryRecorded(
            entryId,
            input.periodId,
            input.assetId,
            taxable,
            estTax,
            input.auditDocHash
        );
    }

    function recordAdjustment(
        uint256 originalEntryId,
        int256 taxableIncomeDelta,
        int256 taxDelta,
        bytes32 justificationHash
    ) external onlyRole(ACCOUNTANT_ROLE) whenNotPaused returns (uint256 adjustmentId) {
        if (_entries[originalEntryId].entryId == 0) revert EntryNotFound(originalEntryId);
        if (justificationHash == bytes32(0)) revert InvalidDocumentHash();

        adjustmentId = ++nextAdjustmentId;

        AuditAdjustment storage adj = _adjustments[adjustmentId];
        adj.adjustmentId = adjustmentId;
        adj.originalEntryId = originalEntryId;
        adj.taxableIncomeDelta = taxableIncomeDelta;
        adj.taxDelta = taxDelta;
        adj.justificationHash = justificationHash;
        adj.recordedAt = block.timestamp;
        adj.recordedBy = msg.sender;

        emit AuditAdjustmentRecorded(
            adjustmentId,
            originalEntryId,
            taxableIncomeDelta,
            taxDelta,
            justificationHash
        );
    }

    function getEntry(uint256 entryId) external view returns (LedgerEntry memory) {
        if (_entries[entryId].entryId == 0) revert EntryNotFound(entryId);
        return _entries[entryId];
    }

    function getEntryByPeriodAndAsset(
        bytes32 periodId,
        bytes32 assetId
    ) external view returns (LedgerEntry memory) {
        uint256 entryId = entryIdByPeriodAndAsset[keccak256(abi.encodePacked(periodId, assetId))];
        if (entryId == 0) revert EntryNotFound(entryId);
        return _entries[entryId];
    }

    function getAdjustment(uint256 adjustmentId) external view returns (AuditAdjustment memory) {
        if (_adjustments[adjustmentId].adjustmentId == 0) {
            revert AdjustmentNotFound(adjustmentId);
        }
        return _adjustments[adjustmentId];
    }

    function setTaxRateBps(uint256 newRateBps) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newRateBps > MAX_TAX_RATE_BPS) revert InvalidTaxRate(newRateBps);
        uint256 oldRate = taxRateBps;
        taxRateBps = newRateBps;
        emit TaxRateUpdated(oldRate, newRateBps);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function _calculateTax(
        uint256 grossRevenue,
        uint256 deductibleOpex,
        uint256 depreciationAmount
    ) internal view returns (uint256 taxable, uint256 estTax) {
        uint256 totalDeductions = deductibleOpex + depreciationAmount;
        taxable = grossRevenue > totalDeductions ? grossRevenue - totalDeductions : 0;
        estTax = (taxable * taxRateBps) / BPS_DENOMINATOR;
    }

    function _storeEntry(
        uint256 entryId,
        EntryInput calldata input,
        uint256 taxable,
        uint256 estTax
    ) internal {
        LedgerEntry storage entry = _entries[entryId];
        entry.entryId = entryId;
        entry.periodId = input.periodId;
        entry.assetId = input.assetId;
        entry.grossRevenue = input.grossRevenue;
        entry.deductibleOpex = input.deductibleOpex;
        entry.depreciationAmount = input.depreciationAmount;
        entry.reserveAllocation = input.reserveAllocation;
        entry.investorDistribution = input.investorDistribution;
        entry.operatorDistribution = input.operatorDistribution;
        entry.taxableIncome = taxable;
        entry.estimatedTax = estTax;
        entry.auditDocHash = input.auditDocHash;
        entry.recordedAt = block.timestamp;
        entry.recordedBy = msg.sender;
    }

    function _updateTotals(
        EntryInput calldata input,
        uint256 taxable,
        uint256 estTax
    ) internal {
        totalGrossRevenue += input.grossRevenue;
        totalDeductibleOpex += input.deductibleOpex;
        totalDepreciation += input.depreciationAmount;
        totalTaxableIncome += taxable;
        totalEstimatedTax += estTax;

        if (input.assetId != bytes32(0)) {
            accumulatedDepreciationByAsset[input.assetId] += input.depreciationAmount;
        }
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}

    uint256[39] private __gap;
}
