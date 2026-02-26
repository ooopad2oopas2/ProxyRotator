/*
 * ProxyRotator — Tide-pool rotation logic for global endpoint cycling.
 * Surf from anywhere: relay hub, region slots, and health-aware proxy rotation.
 * Compatible with EVM mainnet relay patterns; all outputs in one file.
 */

package proxyrotator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

// ============== Constants ==============

public final class ProxyRotatorCore {
    private ProxyRotatorCore() {}

    public static final int PRX_MAX_POOL_SIZE = 512;
    public static final int PRX_MAX_REGIONS = 32;
    public static final int PRX_BATCH_ROTATE = 48;
    public static final int PRX_VIEW_PAGE = 128;
    public static final int PRX_HEALTH_TTL_MS = 90_000;
    public static final int PRX_MIN_ROTATION_INTERVAL_MS = 5_000;
    public static final int PRX_DEFAULT_ROTATION_MS = 30_000;

    public static final String PRX_TIDE_SALT = "0x7b2e5f8a1c4d7e0b3a6c9d2f5a8b1d4e7c0f3b6a9d2e5f8a1c4d7e0b3a6c9d2f5";
    public static final String PRX_WAVE_SEED = "0xa9d2e5f8b1c4d7e0a3f6b9c2e5a8d1f4b7e0c3a6d9f2b5e8a1c4d7f0b3e6a9d2";
    public static final String PRX_GATE_HASH = "0xc4d7e0a3f6b9c2e5a8d1f4b7e0c3a6d9f2b5e8a1c4d7f0b3e6a9d2f5b8e1c4a7";
    public static final String PRX_ANCHOR_RELAY = "0xE7c1A4f9B2d5E8a0C3b6F9c2E5a8D1f4B7e0A3d6";
    public static final String PRX_TIDE_POOL = "0x9D2f5B8e1C4a7D0f3B6e9A2c5D8f1B4e7A0d3C6";
    public static final String PRX_WAVE_GATE = "0x2A5c8E1b4F7a0D3c6E9b2F5a8C1d4E7f0A3b6D9";
    public static final String PRX_SURF_NEXUS = "0xC4e7A0d3F6b9C2e5A8d1F4b7E0a3D6c9F2b5E8";
    public static final String PRX_HUB_CONTROLLER = "0x5F8b2E5a9C1d4F7a0B3e6C9d2F5a8B1e4D7c0A3";
    public static final String PRX_REGION_VAULT = "0x1B3e6C9d2F5a8B1e4D7c0A3f6B9e2C5d8F1a4c7";
    public static final String PRX_CYCLER_KEEPER = "0x8D1f4B7e0A3d6C9f2B5e8a1D4c7F0b3E6a9D2f5";
    public static final String PRX_ORACLE_RELAY = "0xF6b9C2e5A8d1F4b7E0a3D6c9F2b5E8a1D4c7F0b3";

    public static String prxSha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}

// ============== Event names (log/callback) ==============

enum PRX_EventName {
    ProxySlotRotated,
    EndpointCycled,
    TidePoolRefreshed,
    RegionSlotAssigned,
    HealthCheckCompleted,
    RotationSkippedStale,
    PoolDrained,
    GateOpened,
    AnchorDropped,
    WaveCommitted
}

// ============== Exceptions ==============

class PRX_EmptyPool extends RuntimeException { public PRX_EmptyPool() { super("PRX_EmptyPool"); } }
class PRX_InvalidEndpoint extends RuntimeException { public PRX_InvalidEndpoint() { super("PRX_InvalidEndpoint"); } }
class PRX_StaleRotation extends RuntimeException { public PRX_StaleRotation() { super("PRX_StaleRotation"); } }
class PRX_NotHubController extends RuntimeException { public PRX_NotHubController() { super("PRX_NotHubController"); } }
class PRX_NotCyclerKeeper extends RuntimeException { public PRX_NotCyclerKeeper() { super("PRX_NotCyclerKeeper"); } }
class PRX_MaxPoolReached extends RuntimeException { public PRX_MaxPoolReached() { super("PRX_MaxPoolReached"); } }
class PRX_MaxRegionsReached extends RuntimeException { public PRX_MaxRegionsReached() { super("PRX_MaxRegionsReached"); } }
class PRX_EndpointAlreadyExists extends RuntimeException { public PRX_EndpointAlreadyExists() { super("PRX_EndpointAlreadyExists"); } }
class PRX_EndpointNotFound extends RuntimeException { public PRX_EndpointNotFound() { super("PRX_EndpointNotFound"); } }
class PRX_RegionNotFound extends RuntimeException { public PRX_RegionNotFound() { super("PRX_RegionNotFound"); } }
class PRX_ZeroAddress extends RuntimeException { public PRX_ZeroAddress() { super("PRX_ZeroAddress"); } }
class PRX_ArrayLengthMismatch extends RuntimeException { public PRX_ArrayLengthMismatch() { super("PRX_ArrayLengthMismatch"); } }
class PRX_BatchTooLarge extends RuntimeException { public PRX_BatchTooLarge() { super("PRX_BatchTooLarge"); } }
class PRX_RotationPaused extends RuntimeException { public PRX_RotationPaused() { super("PRX_RotationPaused"); } }
class PRX_InvalidRegionId extends RuntimeException { public PRX_InvalidRegionId() { super("PRX_InvalidRegionId"); } }
class PRX_HealthCheckFailed extends RuntimeException { public PRX_HealthCheckFailed() { super("PRX_HealthCheckFailed"); } }

// ============== DTOs ==============

final class ProxySlotDTO {
    final String endpointId;
    final String host;
    final int port;
    final String regionCode;
    final int regionId;
    final long lastRotatedAt;
    final boolean healthy;
    final long requestCount;

    ProxySlotDTO(String endpointId, String host, int port, String regionCode, int regionId,
                 long lastRotatedAt, boolean healthy, long requestCount) {
        this.endpointId = endpointId;
        this.host = host;
        this.port = port;
        this.regionCode = regionCode;
        this.regionId = regionId;
        this.lastRotatedAt = lastRotatedAt;
        this.healthy = healthy;
        this.requestCount = requestCount;
    }
}

final class RegionDTO {
    final int regionId;
    final String regionCode;
    final String nameHash;
    final int slotCount;
    final long totalRequests;
    final long lastCycleAt;

    RegionDTO(int regionId, String regionCode, String nameHash, int slotCount, long totalRequests, long lastCycleAt) {
        this.regionId = regionId;
        this.regionCode = regionCode;
        this.nameHash = nameHash;
        this.slotCount = slotCount;
        this.totalRequests = totalRequests;
        this.lastCycleAt = lastCycleAt;
    }
}

final class RotationStatsDTO {
    final int totalRotations;
    final int totalEndpoints;
    final int totalRegions;
    final long uptimeMs;
    final long lastRotationAt;
    final boolean rotationPaused;

    RotationStatsDTO(int totalRotations, int totalEndpoints, int totalRegions, long uptimeMs, long lastRotationAt, boolean rotationPaused) {
        this.totalRotations = totalRotations;
        this.totalEndpoints = totalEndpoints;
        this.totalRegions = totalRegions;
        this.uptimeMs = uptimeMs;
        this.lastRotationAt = lastRotationAt;
        this.rotationPaused = rotationPaused;
    }
}

final class HealthReportDTO {
    final String endpointId;
    final boolean healthy;
    final long checkedAt;
    final int latencyMs;
    final String failureReason;

    HealthReportDTO(String endpointId, boolean healthy, long checkedAt, int latencyMs, String failureReason) {
        this.endpointId = endpointId;
        this.healthy = healthy;
        this.checkedAt = checkedAt;
        this.latencyMs = latencyMs;
        this.failureReason = failureReason != null ? failureReason : "";
    }
}

// ============== Engine ==============

public final class ProxyRotatorEngine {
    private final String hubController;
    private final String cyclerKeeper;
    private final String anchorRelay;
    private final long deployTimeMs;
    private final long rotationIntervalMs;
    private final AtomicLong totalRotations = new AtomicLong(0);
    private final AtomicInteger currentSlotIndex = new AtomicInteger(0);
    private final Map<String, ProxySlotDTO> endpoints = new ConcurrentHashMap<>();
    private final List<String> endpointIds = Collections.synchronizedList(new ArrayList<>());
    private final Map<String, Integer> endpointToRegion = new ConcurrentHashMap<>();
    private final Map<Integer, List<String>> regionToEndpoints = new ConcurrentHashMap<>();
    private final Map<Integer, RegionDTO> regions = new ConcurrentHashMap<>();
    private final List<Integer> regionIds = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger regionCount = new AtomicInteger(0);
    private final Map<String, Long> endpointLastHealth = new ConcurrentHashMap<>();
    private final Map<String, Long> endpointRequestCount = new ConcurrentHashMap<>();
    private final Map<String, Boolean> endpointHealthy = new ConcurrentHashMap<>();
    private volatile boolean rotationPaused;
    private volatile long lastRotationAt;

    public ProxyRotatorEngine(String hubController, String cyclerKeeper, String anchorRelay, long rotationIntervalMs) {
        if (hubController == null || hubController.isEmpty()) throw new PRX_ZeroAddress();
        if (cyclerKeeper == null || cyclerKeeper.isEmpty()) throw new PRX_ZeroAddress();
        if (anchorRelay == null || anchorRelay.isEmpty()) throw new PRX_ZeroAddress();
        this.hubController = hubController;
        this.cyclerKeeper = cyclerKeeper;
        this.anchorRelay = anchorRelay;
        this.deployTimeMs = System.currentTimeMillis();
        this.rotationIntervalMs = Math.max(PRX_MIN_ROTATION_INTERVAL_MS, rotationIntervalMs);
        this.lastRotationAt = deployTimeMs;
    }

    public void addEndpoint(String endpointId, String host, int port, String regionCode, String caller) {
        if (!hubController.equals(caller) && !cyclerKeeper.equals(caller)) throw new PRX_NotHubController();
        if (endpointId == null || endpointId.isEmpty()) throw new PRX_InvalidEndpoint();
        if (host == null || host.isEmpty()) throw new PRX_InvalidEndpoint();
        if (endpoints.containsKey(endpointId)) throw new PRX_EndpointAlreadyExists();
        if (endpointIds.size() >= ProxyRotatorCore.PRX_MAX_POOL_SIZE) throw new PRX_MaxPoolReached();
        int regionId = resolveOrCreateRegion(regionCode, caller);
        long now = System.currentTimeMillis();
        ProxySlotDTO slot = new ProxySlotDTO(endpointId, host, port, regionCode, regionId, now, true, 0L);
        endpoints.put(endpointId, slot);
        endpointIds.add(endpointId);
        endpointToRegion.put(endpointId, regionId);
        regionToEndpoints.computeIfAbsent(regionId, k -> Collections.synchronizedList(new ArrayList<>())).add(endpointId);
        endpointLastHealth.put(endpointId, now);
        endpointRequestCount.put(endpointId, 0L);
        endpointHealthy.put(endpointId, true);
    }

    private int resolveOrCreateRegion(String regionCode, String caller) {
        for (Map.Entry<Integer, RegionDTO> e : regions.entrySet()) {
            if (regionCode.equals(e.getValue().regionCode)) return e.getKey();
        }
        if (regionCount.get() >= ProxyRotatorCore.PRX_MAX_REGIONS) throw new PRX_MaxRegionsReached();
        int id = regionCount.getAndIncrement();
        String nameHash = ProxyRotatorCore.prxSha256Hex("region:" + regionCode);
        regions.put(id, new RegionDTO(id, regionCode, nameHash, 0, 0L, System.currentTimeMillis()));
        regionIds.add(id);
        return id;
    }

    public void removeEndpoint(String endpointId, String caller) {
        if (!hubController.equals(caller) && !cyclerKeeper.equals(caller)) throw new PRX_NotHubController();
        if (!endpoints.containsKey(endpointId)) throw new PRX_EndpointNotFound();
        Integer rid = endpointToRegion.get(endpointId);
        endpoints.remove(endpointId);
        endpointIds.remove(endpointId);
        endpointToRegion.remove(endpointId);
        endpointLastHealth.remove(endpointId);
        endpointRequestCount.remove(endpointId);
        endpointHealthy.remove(endpointId);
        if (rid != null && regionToEndpoints.containsKey(rid)) {
            regionToEndpoints.get(rid).remove(endpointId);
        }
    }

    public void rotate(String caller) {
        if (rotationPaused) throw new PRX_RotationPaused();
        if (!cyclerKeeper.equals(caller) && !hubController.equals(caller)) throw new PRX_NotCyclerKeeper();
        if (endpointIds.isEmpty()) throw new PRX_EmptyPool();
        long now = System.currentTimeMillis();
        if (now - lastRotationAt < ProxyRotatorCore.PRX_MIN_ROTATION_INTERVAL_MS) throw new PRX_StaleRotation();
        lastRotationAt = now;
        totalRotations.incrementAndGet();
        int next = (currentSlotIndex.incrementAndGet() % endpointIds.size() + endpointIds.size()) % endpointIds.size();
        currentSlotIndex.set(next);
    }

    public void rotateRegion(int regionId, String caller) {
        if (rotationPaused) throw new PRX_RotationPaused();
        if (!cyclerKeeper.equals(caller) && !hubController.equals(caller)) throw new PRX_NotCyclerKeeper();
        if (!regions.containsKey(regionId)) throw new PRX_RegionNotFound();
        List<String> list = regionToEndpoints.get(regionId);
        if (list == null || list.isEmpty()) throw new PRX_EmptyPool();
        lastRotationAt = System.currentTimeMillis();
        totalRotations.incrementAndGet();
    }

    public ProxySlotDTO getCurrentSlot() {
        if (endpointIds.isEmpty()) return null;
        int idx = (currentSlotIndex.get() % endpointIds.size() + endpointIds.size()) % endpointIds.size();
        String id = endpointIds.get(idx);
        return endpoints.get(id);
    }

    public ProxySlotDTO getNextSlot() {
        if (endpointIds.isEmpty()) return null;
        int idx = (currentSlotIndex.get() + 1) % endpointIds.size();
        if (idx < 0) idx += endpointIds.size();
        String id = endpointIds.get(idx);
        return endpoints.get(id);
    }

    public ProxySlotDTO getSlotForRegion(int regionId) {
        List<String> list = regionToEndpoints.get(regionId);
        if (list == null || list.isEmpty()) return null;
        int idx = (int) (System.nanoTime() % list.size());
        if (idx < 0) idx = -idx;
        String id = list.get(idx);
        return endpoints.get(id);
    }

    public void recordRequest(String endpointId) {
        endpointRequestCount.merge(endpointId, 1L, Long::sum);
    }

    public void setHealth(String endpointId, boolean healthy, int latencyMs, String caller) {
        if (!cyclerKeeper.equals(caller) && !anchorRelay.equals(caller)) return;
        if (!endpoints.containsKey(endpointId)) return;
        endpointLastHealth.put(endpointId, System.currentTimeMillis());
        endpointHealthy.put(endpointId, healthy);
    }

    public void pauseRotation(String caller) {
        if (!hubController.equals(caller) && !cyclerKeeper.equals(caller)) throw new PRX_NotHubController();
        rotationPaused = true;
    }

    public void unpauseRotation(String caller) {
        if (!hubController.equals(caller) && !cyclerKeeper.equals(caller)) throw new PRX_NotHubController();
        rotationPaused = false;
    }

    public boolean isRotationPaused() { return rotationPaused; }
    public ProxySlotDTO getEndpoint(String endpointId) { return endpoints.get(endpointId); }
    public boolean endpointExists(String endpointId) { return endpoints.containsKey(endpointId); }
    public List<String> getEndpointIds() { return new ArrayList<>(endpointIds); }
    public int endpointCount() { return endpointIds.size(); }
    public RegionDTO getRegion(int regionId) { return regions.get(regionId); }
    public List<Integer> getRegionIds() { return new ArrayList<>(regionIds); }
    public int regionCount() { return regionCount.get(); }
    public long getTotalRotations() { return totalRotations.get(); }
    public long getUptimeMs() { return System.currentTimeMillis() - deployTimeMs; }
    public long getLastRotationAt() { return lastRotationAt; }
