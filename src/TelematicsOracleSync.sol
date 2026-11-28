// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title TelematicsOracleSync
 * @author Parsa Abolhasani Rad (Aervynx Ecosystem)
 * @notice UUPS upgradeable IoT telematics bridge tracking monotonic odometer, engine hours,
 *         vehicle health index, and dynamic maintenance reserve ratios.
 */
contract TelematicsOracleSync is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    bytes32 public constant ORACLE_FEEDER_ROLE = keccak256("ORACLE_FEEDER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant MAX_RESERVE_BPS = 5000;

    struct VehicleTelemetry {
        uint256 odometerKm;
        uint256 engineHours;
        uint256 fuelEfficiencyBps;
        uint8 healthIndex;
        uint256 lastUpdated;
        bytes32 telemetryDataHash;
        bool maintenanceRequired;
        bool initialized;
    }

    uint256 public baseReserveBps;
    uint256 public elevatedReserveBps;
    uint256 public criticalReserveBps;
    uint8 public alertHealthThreshold;

    bytes32[] public trackedAssets;
    mapping(bytes32 => VehicleTelemetry) public telemetryByAsset;

    event TelemetrySynced(
        bytes32 indexed assetId,
        uint256 odometerKm,
        uint256 engineHours,
        uint8 healthIndex,
        bytes32 telemetryDataHash
    );
    event MaintenanceAlertTriggered(bytes32 indexed assetId, uint8 healthIndex, uint256 odometerKm);
    event MaintenanceAlertCleared(bytes32 indexed assetId, uint8 newHealthIndex);
    event ReservePolicyUpdated(
        uint256 baseBps,
        uint256 elevatedBps,
        uint256 criticalBps,
        uint8 alertThreshold
    );

    error InvalidAddress();
    error InvalidAssetId();
    error InvalidHealthIndex(uint8 healthIndex);
    error InvalidTelemetryHash();
    error OdometerRollbackDetected(uint256 previousKm, uint256 providedKm);
    error EngineHoursRollbackDetected(uint256 previousHours, uint256 providedHours);
    error AssetTelemetryNotInitialized(bytes32 assetId);
    error InvalidReservePolicy();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes telematics reserve policy (10% / 15% / 25%) and access roles.
     */
    function initialize(address admin) public initializer {
        if (admin == address(0)) revert InvalidAddress();

        __AccessControl_init();
        __Pausable_init();

        baseReserveBps = 1000;
        elevatedReserveBps = 1500;
        criticalReserveBps = 2500;
        alertHealthThreshold = 60;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ORACLE_FEEDER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    function syncTelemetry(
        bytes32 assetId,
        uint256 odometerKm,
        uint256 engineHours,
        uint256 fuelEfficiencyBps,
        uint8 healthIndex,
        bytes32 telemetryDataHash
    ) external onlyRole(ORACLE_FEEDER_ROLE) whenNotPaused {
        if (assetId == bytes32(0)) revert InvalidAssetId();
        if (healthIndex > 100) revert InvalidHealthIndex(healthIndex);
        if (telemetryDataHash == bytes32(0)) revert InvalidTelemetryHash();

        VehicleTelemetry storage data = telemetryByAsset[assetId];

        if (!data.initialized) {
            data.initialized = true;
            trackedAssets.push(assetId);
        } else {
            if (odometerKm < data.odometerKm) {
                revert OdometerRollbackDetected(data.odometerKm, odometerKm);
            }
            if (engineHours < data.engineHours) {
                revert EngineHoursRollbackDetected(data.engineHours, engineHours);
            }
        }

        bool wasAlert = data.maintenanceRequired;
        bool isAlert = healthIndex < alertHealthThreshold;

        data.odometerKm = odometerKm;
        data.engineHours = engineHours;
        data.fuelEfficiencyBps = fuelEfficiencyBps;
        data.healthIndex = healthIndex;
        data.lastUpdated = block.timestamp;
        data.telemetryDataHash = telemetryDataHash;
        data.maintenanceRequired = isAlert;

        emit TelemetrySynced(assetId, odometerKm, engineHours, healthIndex, telemetryDataHash);

        if (isAlert) {
            emit MaintenanceAlertTriggered(assetId, healthIndex, odometerKm);
        } else if (wasAlert && !isAlert) {
            emit MaintenanceAlertCleared(assetId, healthIndex);
        }
    }

    function getRecommendedReserveBps(bytes32 assetId) public view returns (uint256) {
        VehicleTelemetry storage data = telemetryByAsset[assetId];
        if (!data.initialized) revert AssetTelemetryNotInitialized(assetId);

        if (data.healthIndex >= 80) {
            return baseReserveBps;
        }
        if (data.healthIndex >= alertHealthThreshold) {
            return elevatedReserveBps;
        }
        return criticalReserveBps;
    }

    function getFleetAverageHealth() external view returns (uint256) {
        uint256 count = trackedAssets.length;
        if (count == 0) {
            return 100;
        }
        uint256 totalHealth;
        for (uint256 i = 0; i < count; ) {
            totalHealth += telemetryByAsset[trackedAssets[i]].healthIndex;
            unchecked {
                ++i;
            }
        }
        return totalHealth / count;
    }

    function trackedAssetsCount() external view returns (uint256) {
        return trackedAssets.length;
    }

    function setReservePolicy(
        uint256 _baseBps,
        uint256 _elevatedBps,
        uint256 _criticalBps,
        uint8 _alertThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (
            _baseBps > _elevatedBps ||
            _elevatedBps > _criticalBps ||
            _criticalBps > MAX_RESERVE_BPS ||
            _alertThreshold == 0 ||
            _alertThreshold > 80
        ) revert InvalidReservePolicy();

        baseReserveBps = _baseBps;
        elevatedReserveBps = _elevatedBps;
        criticalReserveBps = _criticalBps;
        alertHealthThreshold = _alertThreshold;

        emit ReservePolicyUpdated(_baseBps, _elevatedBps, _criticalBps, _alertThreshold);
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

    uint256[43] private __gap;
}
