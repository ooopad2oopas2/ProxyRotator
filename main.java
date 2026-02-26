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
    public String getHubController() { return hubController; }
    public String getCyclerKeeper() { return cyclerKeeper; }
    public String getAnchorRelay() { return anchorRelay; }
    public long getRotationIntervalMs() { return rotationIntervalMs; }

    public RotationStatsDTO getRotationStats() {
        return new RotationStatsDTO(
            (int) totalRotations.get(),
            endpointIds.size(),
            regionCount.get(),
            getUptimeMs(),
            lastRotationAt,
            rotationPaused
        );
    }

    public List<ProxySlotDTO> getEndpointsPaginated(int offset, int limit) {
        int total = endpointIds.size();
        if (offset >= total) return Collections.emptyList();
        if (limit > ProxyRotatorCore.PRX_VIEW_PAGE) limit = ProxyRotatorCore.PRX_VIEW_PAGE;
        int end = Math.min(offset + limit, total);
        List<ProxySlotDTO> out = new ArrayList<>();
        for (int i = offset; i < end; i++) {
            String id = endpointIds.get(i);
            ProxySlotDTO dto = endpoints.get(id);
            if (dto != null) {
                long req = endpointRequestCount.getOrDefault(id, 0L);
                boolean healthy = endpointHealthy.getOrDefault(id, true);
                out.add(new ProxySlotDTO(dto.endpointId, dto.host, dto.port, dto.regionCode, dto.regionId,
                    dto.lastRotatedAt, healthy, req));
            }
        }
        return out;
    }

    public List<String> getEndpointIdsByRegion(int regionId, int offset, int limit) {
        List<String> list = regionToEndpoints.get(regionId);
        if (list == null) return Collections.emptyList();
        list = new ArrayList<>(list);
        int total = list.size();
        if (offset >= total) return Collections.emptyList();
        if (limit > ProxyRotatorCore.PRX_VIEW_PAGE) limit = ProxyRotatorCore.PRX_VIEW_PAGE;
        int end = Math.min(offset + limit, total);
        return new ArrayList<>(list.subList(offset, end));
    }
}

// ============== Validation ==============

final class ProxyRotatorValidation {
    private ProxyRotatorValidation() {}
    static boolean isValidEVMAddress(String addr) {
        if (addr == null) return false;
        String a = addr.startsWith("0x") ? addr.substring(2) : addr;
        return a.length() == 40 && a.chars().allMatch(c -> Character.digit(c, 16) >= 0);
    }
    static boolean isValidEndpointId(String id) {
        return id != null && id.length() >= 8 && id.length() <= 128;
    }
    static boolean isValidPort(int port) {
        return port > 0 && port <= 65535;
    }
    static boolean isValidRegionCode(String code) {
        return code != null && code.length() >= 2 && code.length() <= 16;
    }
}

// ============== API Handlers ==============

final class ProxyRotatorApiHandlers {
    private ProxyRotatorApiHandlers() {}
    static Map<String, Object> getCurrentSlot(ProxyRotatorEngine engine) {
        ProxySlotDTO s = engine.getCurrentSlot();
        if (s == null) return Collections.emptyMap();
        Map<String, Object> m = new HashMap<>();
        m.put("endpointId", s.endpointId);
        m.put("host", s.host);
        m.put("port", s.port);
        m.put("regionCode", s.regionCode);
        m.put("regionId", s.regionId);
        m.put("lastRotatedAt", s.lastRotatedAt);
        m.put("healthy", s.healthy);
        m.put("requestCount", s.requestCount);
        return m;
    }
    static Map<String, Object> getRotationStats(ProxyRotatorEngine engine) {
        RotationStatsDTO r = engine.getRotationStats();
        Map<String, Object> m = new HashMap<>();
        m.put("totalRotations", r.totalRotations);
        m.put("totalEndpoints", r.totalEndpoints);
        m.put("totalRegions", r.totalRegions);
        m.put("uptimeMs", r.uptimeMs);
        m.put("lastRotationAt", r.lastRotationAt);
        m.put("rotationPaused", r.rotationPaused);
        return m;
    }
    static Map<String, Object> listEndpoints(ProxyRotatorEngine engine, int offset, int limit) {
        List<ProxySlotDTO> list = engine.getEndpointsPaginated(offset, limit);
        List<Map<String, Object>> items = new ArrayList<>();
        for (ProxySlotDTO s : list) {
            Map<String, Object> m = new HashMap<>();
            m.put("endpointId", s.endpointId);
            m.put("host", s.host);
            m.put("port", s.port);
            m.put("regionCode", s.regionCode);
            m.put("regionId", s.regionId);
            m.put("lastRotatedAt", s.lastRotatedAt);
            m.put("healthy", s.healthy);
            m.put("requestCount", s.requestCount);
            items.add(m);
        }
        Map<String, Object> out = new HashMap<>();
        out.put("endpoints", items);
        out.put("total", engine.endpointCount());
        out.put("offset", offset);
        out.put("limit", limit);
        return out;
    }
    static Map<String, Object> listRegions(ProxyRotatorEngine engine) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (Integer rid : engine.getRegionIds()) {
            RegionDTO r = engine.getRegion(rid);
            if (r != null) {
                Map<String, Object> m = new HashMap<>();
                m.put("regionId", r.regionId);
                m.put("regionCode", r.regionCode);
                m.put("nameHash", r.nameHash);
                m.put("slotCount", r.slotCount);
                m.put("totalRequests", r.totalRequests);
                m.put("lastCycleAt", r.lastCycleAt);
                items.add(m);
            }
        }
        Map<String, Object> out = new HashMap<>();
        out.put("regions", items);
        out.put("total", engine.regionCount());
        return out;
    }
}

// ============== Batch operations ==============

final class ProxyRotatorBatch {
    private ProxyRotatorBatch() {}
    static void addEndpointsBatch(ProxyRotatorEngine engine, List<String> endpointIds, List<String> hosts,
                                  List<Integer> ports, List<String> regionCodes, String caller) {
        if (endpointIds.size() != hosts.size() || endpointIds.size() != ports.size() || endpointIds.size() != regionCodes.size())
            throw new PRX_ArrayLengthMismatch();
        if (endpointIds.size() > ProxyRotatorCore.PRX_BATCH_ROTATE) throw new PRX_BatchTooLarge();
        for (int i = 0; i < endpointIds.size(); i++) {
            engine.addEndpoint(endpointIds.get(i), hosts.get(i), ports.get(i), regionCodes.get(i), caller);
        }
    }
}

// ============== Health checker ==============

final class ProxyRotatorHealthChecker {
    private ProxyRotatorHealthChecker() {}
    static HealthReportDTO checkEndpoint(ProxyRotatorEngine engine, String endpointId, String caller) {
        if (!engine.endpointExists(endpointId)) return null;
        long now = System.currentTimeMillis();
        boolean healthy = new SecureRandom().nextInt(100) > 15;
        int latencyMs = 20 + new SecureRandom().nextInt(180);
        engine.setHealth(endpointId, healthy, latencyMs, caller);
        return new HealthReportDTO(endpointId, healthy, now, latencyMs, healthy ? null : "simulated_failure");
    }
    static List<HealthReportDTO> checkAll(ProxyRotatorEngine engine, String caller) {
        List<HealthReportDTO> out = new ArrayList<>();
        for (String id : engine.getEndpointIds()) {
            HealthReportDTO r = checkEndpoint(engine, id, caller);
            if (r != null) out.add(r);
        }
        return out;
    }
}

// ============== Event logger ==============

final class ProxyRotatorEventLog {
    private static final List<String> log = Collections.synchronizedList(new ArrayList<>());
    private static final int MAX_LOG = 500;
    static void emit(PRX_EventName event, String detail) {
        String line = System.currentTimeMillis() + " " + event.name() + " " + (detail != null ? detail : "");
        log.add(line);
        while (log.size() > MAX_LOG) log.remove(0);
    }
    static List<String> getRecent(int n) {
        int size = log.size();
        if (n <= 0 || size == 0) return Collections.emptyList();
        int start = Math.max(0, size - n);
        return new ArrayList<>(log.subList(start, size));
    }
}

// ============== Region helpers ==============

final class ProxyRotatorRegionHelper {
    private ProxyRotatorRegionHelper() {}
    static final String[] DEFAULT_REGION_CODES = { "NA-US", "NA-CA", "EU-DE", "EU-NL", "APAC-SG", "APAC-JP", "SA-BR", "OC-AU" };
    static String regionCodeFromIndex(int index) {
        if (index >= 0 && index < DEFAULT_REGION_CODES.length) return DEFAULT_REGION_CODES[index];
        return "REG-" + index;
    }
    static int regionIndexFromCode(String code) {
        for (int i = 0; i < DEFAULT_REGION_CODES.length; i++) {
            if (DEFAULT_REGION_CODES[i].equals(code)) return i;
        }
        return -1;
    }
}

// ============== Id generators ==============

final class ProxyRotatorIdGen {
    private static final AtomicLong counter = new AtomicLong(1000);
    static String nextEndpointId() {
        return "ep-" + counter.incrementAndGet() + "-" + ProxyRotatorCore.prxSha256Hex("ep" + System.nanoTime()).substring(0, 12);
    }
    static String slotIdFromHostPort(String host, int port) {
        return ProxyRotatorCore.prxSha256Hex(host + ":" + port);
    }
}

// ============== Extended views ==============

final class ProxyRotatorEngineViews {
    private ProxyRotatorEngineViews() {}
    static List<ProxySlotDTO> getHealthyEndpoints(ProxyRotatorEngine engine) {
        return engine.getEndpointIds().stream()
            .map(engine::getEndpoint)
            .filter(Objects::nonNull)
            .filter(s -> s.healthy)
            .collect(Collectors.toList());
    }
    static ProxySlotDTO getRandomSlot(ProxyRotatorEngine engine) {
        List<String> ids = engine.getEndpointIds();
        if (ids.isEmpty()) return null;
        int idx = new SecureRandom().nextInt(ids.size());
        return engine.getEndpoint(ids.get(idx));
    }
    static ProxySlotDTO getRandomSlotForRegion(ProxyRotatorEngine engine, int regionId) {
        List<String> list = engine.getEndpointIdsByRegion(regionId, 0, ProxyRotatorCore.PRX_VIEW_PAGE);
        if (list.isEmpty()) return null;
        int idx = new SecureRandom().nextInt(list.size());
        return engine.getEndpoint(list.get(idx));
    }
    static long totalRequestsAcrossPool(ProxyRotatorEngine engine) {
        long sum = 0;
        for (String id : engine.getEndpointIds()) {
            ProxySlotDTO s = engine.getEndpoint(id);
            if (s != null) sum += s.requestCount;
        }
        return sum;
    }
}

// ============== Config ==============

final class ProxyRotatorConfig {
    static final String CONFIG_HUB = ProxyRotatorCore.PRX_HUB_CONTROLLER;
    static final String CONFIG_CYCLER = ProxyRotatorCore.PRX_CYCLER_KEEPER;
    static final String CONFIG_ANCHOR = ProxyRotatorCore.PRX_ANCHOR_RELAY;
    static final String CONFIG_TIDE_POOL = ProxyRotatorCore.PRX_TIDE_POOL;
    static final String CONFIG_WAVE_GATE = ProxyRotatorCore.PRX_WAVE_GATE;
    static final String CONFIG_NEXUS = ProxyRotatorCore.PRX_SURF_NEXUS;
    static final String CONFIG_REGION_VAULT = ProxyRotatorCore.PRX_REGION_VAULT;
    static final String CONFIG_ORACLE = ProxyRotatorCore.PRX_ORACLE_RELAY;
    static final int CONFIG_MAX_POOL = ProxyRotatorCore.PRX_MAX_POOL_SIZE;
    static final int CONFIG_MAX_REGIONS = ProxyRotatorCore.PRX_MAX_REGIONS;
    static final int CONFIG_ROTATION_MS = ProxyRotatorCore.PRX_DEFAULT_ROTATION_MS;
}

// ============== Main ==============

class ProxyRotatorMain {
    public static void main(String[] args) {
        String hub = ProxyRotatorCore.PRX_HUB_CONTROLLER;
        String cycler = ProxyRotatorCore.PRX_CYCLER_KEEPER;
        String anchor = ProxyRotatorCore.PRX_ANCHOR_RELAY;
        ProxyRotatorEngine engine = new ProxyRotatorEngine(hub, cycler, anchor, ProxyRotatorCore.PRX_DEFAULT_ROTATION_MS);
        for (int i = 0; i < 5; i++) {
            String epId = ProxyRotatorIdGen.nextEndpointId();
            String region = ProxyRotatorRegionHelper.regionCodeFromIndex(i % ProxyRotatorRegionHelper.DEFAULT_REGION_CODES.length);
            engine.addEndpoint(epId, "proxy" + i + ".surf.example.com", 8080 + i, region, hub);
        }
        engine.rotate(cycler);
        ProxySlotDTO current = engine.getCurrentSlot();
        System.out.println("ProxyRotator run OK. Current slot: " + (current != null ? current.endpointId : "none"));
        System.out.println("Stats: " + ProxyRotatorApiHandlers.getRotationStats(engine));
    }
}

// ============== Additional API responses ==============

final class ProxyRotatorSlotResponse {
    final Map<String, Object> current;
    final Map<String, Object> next;
    final RotationStatsDTO stats;
    ProxyRotatorSlotResponse(Map<String, Object> current, Map<String, Object> next, RotationStatsDTO stats) {
        this.current = current;
        this.next = next;
        this.stats = stats;
    }
    Map<String, Object> toMap() {
        Map<String, Object> m = new HashMap<>();
        m.put("current", current);
        m.put("next", next);
        m.put("totalRotations", stats.totalRotations);
        m.put("totalEndpoints", stats.totalEndpoints);
        m.put("uptimeMs", stats.uptimeMs);
        return m;
    }
}

// ============== Surf-from-anywhere router ==============

final class SurfFromAnywhereRouter {
    private final ProxyRotatorEngine engine;
    private final String relayAddress;

    SurfFromAnywhereRouter(ProxyRotatorEngine engine, String relayAddress) {
        this.engine = engine;
        this.relayAddress = relayAddress;
    }

    public ProxySlotDTO routeByRegion(String regionCode) {
        for (Integer rid : engine.getRegionIds()) {
            RegionDTO r = engine.getRegion(rid);
            if (r != null && regionCode.equals(r.regionCode))
                return engine.getSlotForRegion(rid);
        }
        return engine.getCurrentSlot();
    }

    public ProxySlotDTO routeRoundRobin() {
        engine.rotate(relayAddress);
        return engine.getCurrentSlot();
    }

    public ProxySlotDTO routeRandom() {
        return ProxyRotatorEngineViews.getRandomSlot(engine);
    }

    public ProxySlotDTO routeHealthyOnly() {
        List<ProxySlotDTO> healthy = ProxyRotatorEngineViews.getHealthyEndpoints(engine);
        if (healthy.isEmpty()) return engine.getCurrentSlot();
        return healthy.get(new SecureRandom().nextInt(healthy.size()));
    }
}

// ============== Tide pool manager ==============

final class TidePoolManager {
    private final ProxyRotatorEngine engine;
    private final String keeper;

    TidePoolManager(ProxyRotatorEngine engine, String keeper) {
        this.engine = engine;
        this.keeper = keeper;
    }

    public void refreshPool(List<String> endpointIds, List<String> hosts, List<Integer> ports, List<String> regionCodes) {
        ProxyRotatorBatch.addEndpointsBatch(engine, endpointIds, hosts, ports, regionCodes, keeper);
        ProxyRotatorEventLog.emit(PRX_EventName.TidePoolRefreshed, "count=" + endpointIds.size());
    }

    public void drainPool() {
        for (String id : new ArrayList<>(engine.getEndpointIds())) {
            try {
                engine.removeEndpoint(id, keeper);
            } catch (Exception ignored) {}
        }
        ProxyRotatorEventLog.emit(PRX_EventName.PoolDrained, null);
    }

    public int poolSize() {
        return engine.endpointCount();
    }
}

// ============== Wave gate ==============

final class WaveGate {
    private static final long GATE_OPEN_INTERVAL_MS = 60_000;
    private final ProxyRotatorEngine engine;
    private final String gateKeeper;
    private volatile long lastGateOpen;

    WaveGate(ProxyRotatorEngine engine, String gateKeeper) {
        this.engine = engine;
        this.gateKeeper = gateKeeper;
        this.lastGateOpen = System.currentTimeMillis();
    }

    public boolean requestPass() {
        long now = System.currentTimeMillis();
        if (now - lastGateOpen >= GATE_OPEN_INTERVAL_MS) {
            lastGateOpen = now;
            ProxyRotatorEventLog.emit(PRX_EventName.GateOpened, null);
            return true;
        }
        return false;
    }

    public void forceOpen(String caller) {
        if (!gateKeeper.equals(caller)) return;
        lastGateOpen = System.currentTimeMillis();
        ProxyRotatorEventLog.emit(PRX_EventName.GateOpened, "forced");
    }
}

// ============== Anchor relay ==============

final class AnchorRelay {
    private final ProxyRotatorEngine engine;
    private final String relayAddr;
    private final Map<String, Long> anchorDrops = new ConcurrentHashMap<>();

    AnchorRelay(ProxyRotatorEngine engine, String relayAddr) {
        this.engine = engine;
        this.relayAddr = relayAddr;
    }

    public void dropAnchor(String endpointId) {
        anchorDrops.put(endpointId, System.currentTimeMillis());
        ProxyRotatorEventLog.emit(PRX_EventName.AnchorDropped, endpointId);
    }

    public boolean isAnchored(String endpointId) {
        Long t = anchorDrops.get(endpointId);
        if (t == null) return false;
        return System.currentTimeMillis() - t < 300_000;
    }

    public void liftAnchor(String endpointId, String caller) {
        if (!relayAddr.equals(caller)) return;
        anchorDrops.remove(endpointId);
    }
}

// ============== Wave committer ==============

final class WaveCommitter {
    private final ProxyRotatorEngine engine;
    private final String keeper;
    private final List<String> committedWaves = Collections.synchronizedList(new ArrayList<>());

    WaveCommitter(ProxyRotatorEngine engine, String keeper) {
        this.engine = engine;
        this.keeper = keeper;
    }

    public void commitWave(String waveId, String endpointId) {
        if (engine.endpointExists(endpointId)) {
            committedWaves.add(waveId + ":" + endpointId);
            ProxyRotatorEventLog.emit(PRX_EventName.WaveCommitted, waveId);
        }
    }

    public List<String> getCommittedWaves(int offset, int limit) {
        int size = committedWaves.size();
        if (offset >= size) return Collections.emptyList();
        int end = Math.min(offset + limit, size);
        return new ArrayList<>(committedWaves.subList(offset, end));
    }
}

// ============== Export constants ==============

final class ProxyRotatorConstants {
    static final int MAX_POOL_SIZE = ProxyRotatorCore.PRX_MAX_POOL_SIZE;
    static final int MAX_REGIONS = ProxyRotatorCore.PRX_MAX_REGIONS;
    static final int BATCH_ROTATE = ProxyRotatorCore.PRX_BATCH_ROTATE;
    static final int VIEW_PAGE = ProxyRotatorCore.PRX_VIEW_PAGE;
    static final String TIDE_SALT = ProxyRotatorCore.PRX_TIDE_SALT;
    static final String WAVE_SEED = ProxyRotatorCore.PRX_WAVE_SEED;
    static final String ANCHOR_RELAY = ProxyRotatorCore.PRX_ANCHOR_RELAY;
    static final String TIDE_POOL = ProxyRotatorCore.PRX_TIDE_POOL;
    static final String WAVE_GATE_ADDR = ProxyRotatorCore.PRX_WAVE_GATE;
    static final String SURF_NEXUS = ProxyRotatorCore.PRX_SURF_NEXUS;
}

// ============== Integration adapter ==============

final class ProxyRotatorIntegrationAdapter {
    private final ProxyRotatorEngine engine;
    private final SurfFromAnywhereRouter router;
    private final TidePoolManager tidePool;
    private final WaveGate waveGate;
    private final AnchorRelay anchorRelay;
    private final WaveCommitter waveCommitter;

    ProxyRotatorIntegrationAdapter(ProxyRotatorEngine engine) {
        this.engine = engine;
        this.router = new SurfFromAnywhereRouter(engine, ProxyRotatorCore.PRX_ORACLE_RELAY);
        this.tidePool = new TidePoolManager(engine, ProxyRotatorCore.PRX_CYCLER_KEEPER);
        this.waveGate = new WaveGate(engine, ProxyRotatorCore.PRX_HUB_CONTROLLER);
        this.anchorRelay = new AnchorRelay(engine, ProxyRotatorCore.PRX_ANCHOR_RELAY);
        this.waveCommitter = new WaveCommitter(engine, ProxyRotatorCore.PRX_CYCLER_KEEPER);
    }

    public Map<String, Object> fullStatus() {
        Map<String, Object> m = new HashMap<>();
        m.put("engine", ProxyRotatorApiHandlers.getRotationStats(engine));
        m.put("currentSlot", ProxyRotatorApiHandlers.getCurrentSlot(engine));
        m.put("poolSize", tidePool.poolSize());
        m.put("events", ProxyRotatorEventLog.getRecent(20));
        return m;
    }

    public ProxySlotDTO route(String strategy, String regionCode) {
        switch (strategy != null ? strategy : "roundRobin") {
            case "region":
                return router.routeByRegion(regionCode != null ? regionCode : "NA-US");
            case "random":
                return router.routeRandom();
            case "healthy":
                return router.routeHealthyOnly();
            default:
                return router.routeRoundRobin();
        }
    }
}

// ============== Serialization helpers ==============

final class ProxyRotatorSerialization {
    private ProxyRotatorSerialization() {}
    static Map<String, Object> slotToMap(ProxySlotDTO s) {
        if (s == null) return Collections.emptyMap();
        Map<String, Object> m = new HashMap<>();
        m.put("endpointId", s.endpointId);
        m.put("host", s.host);
        m.put("port", s.port);
        m.put("regionCode", s.regionCode);
        m.put("regionId", s.regionId);
        m.put("lastRotatedAt", s.lastRotatedAt);
        m.put("healthy", s.healthy);
        m.put("requestCount", s.requestCount);
        return m;
    }
    static Map<String, Object> regionToMap(RegionDTO r) {
        if (r == null) return Collections.emptyMap();
        Map<String, Object> m = new HashMap<>();
        m.put("regionId", r.regionId);
        m.put("regionCode", r.regionCode);
        m.put("nameHash", r.nameHash);
        m.put("slotCount", r.slotCount);
        m.put("totalRequests", r.totalRequests);
        m.put("lastCycleAt", r.lastCycleAt);
        return m;
    }
}

// ============== Rate limiter ==============

final class ProxyRotatorRateLimiter {
    private final Map<String, long[]> keyToTimestamps = new ConcurrentHashMap<>();
    private final int maxRequestsPerWindow;
    private final long windowMs;

    ProxyRotatorRateLimiter(int maxRequestsPerWindow, long windowMs) {
        this.maxRequestsPerWindow = maxRequestsPerWindow;
        this.windowMs = windowMs;
    }

    public boolean allow(String key) {
        long now = System.currentTimeMillis();
        long[] timestamps = keyToTimestamps.computeIfAbsent(key, k -> new long[maxRequestsPerWindow + 1]);
        int count = (int) timestamps[0];
        for (int i = 1; i <= count; i++) {
            if (now - timestamps[i] > windowMs) {
                timestamps[i] = timestamps[count];
                count--;
                i--;
            }
        }
        if (count >= maxRequestsPerWindow) return false;
        timestamps[0] = count + 1;
        timestamps[count + 1] = now;
        return true;
    }
}

// ============== Metrics ==============

final class ProxyRotatorMetrics {
    private final ProxyRotatorEngine engine;
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong failedRotations = new AtomicLong(0);

    ProxyRotatorMetrics(ProxyRotatorEngine engine) {
        this.engine = engine;
    }

    public void recordRequest() { totalRequests.incrementAndGet(); }
    public void recordFailedRotation() { failedRotations.incrementAndGet(); }
    public long getTotalRequests() { return totalRequests.get(); }
    public long getFailedRotations() { return failedRotations.get(); }

    public Map<String, Object> snapshot() {
        Map<String, Object> m = new HashMap<>();
        m.put("totalRequests", totalRequests.get());
        m.put("failedRotations", failedRotations.get());
        m.put("totalRotations", engine.getTotalRotations());
        m.put("endpointCount", engine.endpointCount());
        m.put("uptimeMs", engine.getUptimeMs());
        return m;
    }
}

// ============== Safe launcher (EVM mainnet style) ==============

final class ProxyRotatorSafeLauncher {
    private ProxyRotatorSafeLauncher() {}
    static ProxyRotatorEngine launch(String hub, String cycler, String anchor) {
        if (!ProxyRotatorValidation.isValidEVMAddress(hub)) throw new PRX_ZeroAddress();
        if (!ProxyRotatorValidation.isValidEVMAddress(cycler)) throw new PRX_ZeroAddress();
        if (!ProxyRotatorValidation.isValidEVMAddress(anchor)) throw new PRX_ZeroAddress();
        return new ProxyRotatorEngine(hub, cycler, anchor, ProxyRotatorCore.PRX_DEFAULT_ROTATION_MS);
    }
    static ProxyRotatorEngine launchWithDefaults() {
        return launch(ProxyRotatorCore.PRX_HUB_CONTROLLER, ProxyRotatorCore.PRX_CYCLER_KEEPER, ProxyRotatorCore.PRX_ANCHOR_RELAY);
    }
}

// ============== Additional event types ==============

final class ProxyRotatorEventTypes {
    static final String PROXY_SLOT_ROTATED = PRX_EventName.ProxySlotRotated.name();
    static final String ENDPOINT_CYCLED = PRX_EventName.EndpointCycled.name();
    static final String TIDE_POOL_REFRESHED = PRX_EventName.TidePoolRefreshed.name();
    static final String REGION_SLOT_ASSIGNED = PRX_EventName.RegionSlotAssigned.name();
    static final String HEALTH_CHECK_COMPLETED = PRX_EventName.HealthCheckCompleted.name();
    static final String ROTATION_SKIPPED_STALE = PRX_EventName.RotationSkippedStale.name();
    static final String POOL_DRAINED = PRX_EventName.PoolDrained.name();
    static final String GATE_OPENED = PRX_EventName.GateOpened.name();
    static final String ANCHOR_DROPPED = PRX_EventName.AnchorDropped.name();
    static final String WAVE_COMMITTED = PRX_EventName.WaveCommitted.name();
}

// ============== Additional DTOs ==============

final class LatencySnapshotDTO {
    final String endpointId;
    final int p50Ms;
    final int p95Ms;
    final int p99Ms;
    final int sampleCount;
    LatencySnapshotDTO(String endpointId, int p50Ms, int p95Ms, int p99Ms, int sampleCount) {
        this.endpointId = endpointId;
        this.p50Ms = p50Ms;
        this.p95Ms = p95Ms;
        this.p99Ms = p99Ms;
        this.sampleCount = sampleCount;
    }
}

final class PoolSummaryDTO {
    final int totalSlots;
    final int healthySlots;
    final int regionCount;
    final long totalRequestsLastHour;
    final long lastRotationEpochMs;
    PoolSummaryDTO(int totalSlots, int healthySlots, int regionCount, long totalRequestsLastHour, long lastRotationEpochMs) {
        this.totalSlots = totalSlots;
        this.healthySlots = healthySlots;
        this.regionCount = regionCount;
        this.totalRequestsLastHour = totalRequestsLastHour;
        this.lastRotationEpochMs = lastRotationEpochMs;
    }
}

final class EndpointAuditDTO {
    final String endpointId;
    final String action;
    final long atEpochMs;
    final String actorAddress;
    EndpointAuditDTO(String endpointId, String action, long atEpochMs, String actorAddress) {
        this.endpointId = endpointId;
        this.action = action;
        this.atEpochMs = atEpochMs;
        this.actorAddress = actorAddress;
    }
}

final class RegionWeightDTO {
    final int regionId;
    final String regionCode;
    final int weightBps;
    final int slotCount;
    RegionWeightDTO(int regionId, String regionCode, int weightBps, int slotCount) {
        this.regionId = regionId;
        this.regionCode = regionCode;
        this.weightBps = weightBps;
        this.slotCount = slotCount;
    }
}

// ============== Extended API handlers ==============

final class ProxyRotatorApiHandlersExtended {
    private ProxyRotatorApiHandlersExtended() {}
    static Map<String, Object> getSlotWithRegion(ProxyRotatorEngine engine, String regionCode) {
        for (Integer rid : engine.getRegionIds()) {
            RegionDTO r = engine.getRegion(rid);
            if (r != null && regionCode.equals(r.regionCode)) {
                ProxySlotDTO slot = engine.getSlotForRegion(rid);
                return ProxyRotatorSerialization.slotToMap(slot);
            }
        }
        return ProxyRotatorSerialization.slotToMap(engine.getCurrentSlot());
    }
    static Map<String, Object> getHealthSummary(ProxyRotatorEngine engine) {
        int healthy = 0;
        int total = engine.endpointCount();
        for (String id : engine.getEndpointIds()) {
            ProxySlotDTO s = engine.getEndpoint(id);
            if (s != null && s.healthy) healthy++;
        }
        Map<String, Object> m = new HashMap<>();
        m.put("healthyCount", healthy);
        m.put("totalCount", total);
        m.put("healthyPct", total > 0 ? (100 * healthy / total) : 0);
        return m;
    }
    static Map<String, Object> getPoolSummary(ProxyRotatorEngine engine) {
        int healthy = 0;
        for (String id : engine.getEndpointIds()) {
            ProxySlotDTO s = engine.getEndpoint(id);
            if (s != null && s.healthy) healthy++;
        }
        long totalReq = ProxyRotatorEngineViews.totalRequestsAcrossPool(engine);
        PoolSummaryDTO dto = new PoolSummaryDTO(engine.endpointCount(), healthy, engine.regionCount(), totalReq, engine.getLastRotationAt());
        Map<String, Object> m = new HashMap<>();
        m.put("totalSlots", dto.totalSlots);
        m.put("healthySlots", dto.healthySlots);
        m.put("regionCount", dto.regionCount);
        m.put("totalRequestsLastHour", dto.totalRequestsLastHour);
        m.put("lastRotationEpochMs", dto.lastRotationEpochMs);
        return m;
    }
    static List<Map<String, Object>> getEndpointsByRegion(ProxyRotatorEngine engine, int regionId) {
        List<String> ids = engine.getEndpointIdsByRegion(regionId, 0, ProxyRotatorCore.PRX_VIEW_PAGE);
        List<Map<String, Object>> out = new ArrayList<>();
        for (String id : ids) {
            ProxySlotDTO s = engine.getEndpoint(id);
            if (s != null) out.add(ProxyRotatorSerialization.slotToMap(s));
        }
        return out;
    }
}

// ============== Pagination helpers ==============

final class ProxyRotatorPagination {
    private ProxyRotatorPagination() {}
    static final int DEFAULT_PAGE_SIZE = 24;
    static int safeOffset(int offset) { return Math.max(0, offset); }
    static int safeLimit(int limit) {
        if (limit <= 0) return DEFAULT_PAGE_SIZE;
        return Math.min(limit, ProxyRotatorCore.PRX_VIEW_PAGE);
    }
    static int totalPages(int totalItems, int pageSize) {
        if (pageSize <= 0) return 0;
        return (totalItems + pageSize - 1) / pageSize;
    }
    static int pageStart(int page, int pageSize) { return page * pageSize; }
}

// ============== Region weight resolver ==============

final class ProxyRotatorRegionWeight {
    private final Map<Integer, Integer> regionWeightBps = new ConcurrentHashMap<>();
    private final ProxyRotatorEngine engine;

    ProxyRotatorRegionWeight(ProxyRotatorEngine engine) {
        this.engine = engine;
        for (Integer rid : engine.getRegionIds()) {
            regionWeightBps.put(rid, 1000);
        }
    }

    public void setWeight(int regionId, int weightBps) {
        if (engine.getRegion(regionId) != null) regionWeightBps.put(regionId, Math.max(0, Math.min(10000, weightBps)));
    }

    public int getWeight(int regionId) {
        return regionWeightBps.getOrDefault(regionId, 1000);
    }

    public List<RegionWeightDTO> getAllWeights() {
        List<RegionWeightDTO> out = new ArrayList<>();
        for (Integer rid : engine.getRegionIds()) {
            RegionDTO r = engine.getRegion(rid);
            if (r != null) {
                int slots = engine.getEndpointIdsByRegion(rid, 0, Integer.MAX_VALUE).size();
                out.add(new RegionWeightDTO(rid, r.regionCode, regionWeightBps.getOrDefault(rid, 1000), slots));
            }
        }
        return out;
    }

    public ProxySlotDTO selectByWeight() {
        List<RegionWeightDTO> weights = getAllWeights();
        int totalBps = 0;
        for (RegionWeightDTO w : weights) totalBps += w.weightBps;
        if (totalBps <= 0) return engine.getCurrentSlot();
        int r = new SecureRandom().nextInt(totalBps);
        for (RegionWeightDTO w : weights) {
            if (r < w.weightBps) return engine.getSlotForRegion(w.regionId);
            r -= w.weightBps;
        }
        return engine.getCurrentSlot();
    }
}

// ============== Sticky session helper ==============

final class ProxyRotatorStickySession {
    private final Map<String, String> sessionToEndpoint = new ConcurrentHashMap<>();
    private final long stickyTtlMs;
    private final Map<String, Long> sessionExpiry = new ConcurrentHashMap<>();

    ProxyRotatorStickySession(long stickyTtlMs) {
        this.stickyTtlMs = stickyTtlMs;
    }

    public ProxySlotDTO resolve(ProxyRotatorEngine engine, String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) return engine.getCurrentSlot();
        Long exp = sessionExpiry.get(sessionId);
        if (exp != null && System.currentTimeMillis() > exp) {
            sessionToEndpoint.remove(sessionId);
            sessionExpiry.remove(sessionId);
            return engine.getCurrentSlot();
        }
        String epId = sessionToEndpoint.get(sessionId);
        if (epId != null && engine.endpointExists(epId)) {
            return engine.getEndpoint(epId);
        }
        ProxySlotDTO slot = engine.getCurrentSlot();
        if (slot != null) {
            sessionToEndpoint.put(sessionId, slot.endpointId);
            sessionExpiry.put(sessionId, System.currentTimeMillis() + stickyTtlMs);
        }
        return slot;
    }

    public void clear(String sessionId) {
        sessionToEndpoint.remove(sessionId);
        sessionExpiry.remove(sessionId);
    }
}

// ============== Backup slot resolver ==============

final class ProxyRotatorBackupResolver {
    private final ProxyRotatorEngine engine;
    private final int maxFallbackAttempts;

    ProxyRotatorBackupResolver(ProxyRotatorEngine engine, int maxFallbackAttempts) {
        this.engine = engine;
        this.maxFallbackAttempts = Math.max(1, Math.min(maxFallbackAttempts, engine.endpointCount()));
    }

    public ProxySlotDTO resolveWithFallback(ProxyRotatorEngine engine, String preferredRegion) {
        ProxySlotDTO primary = null;
        for (Integer rid : engine.getRegionIds()) {
            RegionDTO r = engine.getRegion(rid);
            if (r != null && (preferredRegion == null || preferredRegion.equals(r.regionCode))) {
                primary = engine.getSlotForRegion(rid);
                break;
            }
        }
        if (primary != null && primary.healthy) return primary;
        List<ProxySlotDTO> healthy = ProxyRotatorEngineViews.getHealthyEndpoints(engine);
        if (healthy.isEmpty()) return engine.getCurrentSlot();
        int attempts = Math.min(maxFallbackAttempts, healthy.size());
        return healthy.get(new SecureRandom().nextInt(attempts));
    }
}

// ============== Geo lookup simulation ==============

final class ProxyRotatorGeoSim {
    private static final String[] COUNTRY_CODES = { "US", "CA", "DE", "NL", "SG", "JP", "BR", "AU", "UK", "FR" };
    private static final Map<String, String> COUNTRY_TO_REGION = new HashMap<>();
    static {
        COUNTRY_TO_REGION.put("US", "NA-US");
        COUNTRY_TO_REGION.put("CA", "NA-CA");
        COUNTRY_TO_REGION.put("DE", "EU-DE");
        COUNTRY_TO_REGION.put("NL", "EU-NL");
        COUNTRY_TO_REGION.put("SG", "APAC-SG");
        COUNTRY_TO_REGION.put("JP", "APAC-JP");
        COUNTRY_TO_REGION.put("BR", "SA-BR");
        COUNTRY_TO_REGION.put("AU", "OC-AU");
        COUNTRY_TO_REGION.put("UK", "EU-NL");
        COUNTRY_TO_REGION.put("FR", "EU-DE");
    }

    static String regionFromCountry(String countryCode) {
        if (countryCode == null) return "NA-US";
        String r = COUNTRY_TO_REGION.get(countryCode.toUpperCase());
        return r != null ? r : "NA-US";
    }

    static String randomCountryCode() {
        return COUNTRY_CODES[new SecureRandom().nextInt(COUNTRY_CODES.length)];
    }
}

// ============== Rotation scheduler sim ==============

final class ProxyRotatorSchedulerSim {
    private final ProxyRotatorEngine engine;
    private final String cycler;
    private final long intervalMs;
    private volatile long lastRun;

    ProxyRotatorSchedulerSim(ProxyRotatorEngine engine, String cycler, long intervalMs) {
        this.engine = engine;
        this.cycler = cycler;
        this.intervalMs = Math.max(ProxyRotatorCore.PRX_MIN_ROTATION_INTERVAL_MS, intervalMs);
        this.lastRun = System.currentTimeMillis();
    }

    public boolean maybeRotate() {
        long now = System.currentTimeMillis();
        if (now - lastRun < intervalMs) return false;
        if (engine.isRotationPaused() || engine.endpointCount() == 0) return false;
        try {
            engine.rotate(cycler);
            lastRun = now;
            ProxyRotatorEventLog.emit(PRX_EventName.ProxySlotRotated, null);
            return true;
        } catch (Exception e) {
            ProxyRotatorEventLog.emit(PRX_EventName.RotationSkippedStale, e.getMessage());
            return false;
        }
    }
}

// ============== Endpoint priority queue ==============

final class ProxyRotatorPriorityQueue {
    private final ProxyRotatorEngine engine;
    private final Map<String, Integer> endpointPriority = new ConcurrentHashMap<>();

    ProxyRotatorPriorityQueue(ProxyRotatorEngine engine) {
        this.engine = engine;
    }

    public void setPriority(String endpointId, int priority) {
        if (engine.endpointExists(endpointId)) endpointPriority.put(endpointId, priority);
    }

    public ProxySlotDTO getHighestPriorityHealthy() {
        List<ProxySlotDTO> healthy = ProxyRotatorEngineViews.getHealthyEndpoints(engine);
        if (healthy.isEmpty()) return engine.getCurrentSlot();
        return healthy.stream()
            .max(Comparator.comparingInt(s -> endpointPriority.getOrDefault(s.endpointId, 0)))
            .orElse(engine.getCurrentSlot());
    }
}

// ============== Audit trail ==============

final class ProxyRotatorAuditTrail {
    private static final List<EndpointAuditDTO> trail = Collections.synchronizedList(new ArrayList<>());
    private static final int MAX_AUDIT = 1000;

    static void record(String endpointId, String action, String actorAddress) {
        trail.add(new EndpointAuditDTO(endpointId, action, System.currentTimeMillis(), actorAddress != null ? actorAddress : ""));
        while (trail.size() > MAX_AUDIT) trail.remove(0);
    }

    static List<EndpointAuditDTO> getRecent(int n) {
        int size = trail.size();
        if (n <= 0 || size == 0) return Collections.emptyList();
        int start = Math.max(0, size - n);
        return new ArrayList<>(trail.subList(start, size));
    }
}

// ============== Checksum / verification ==============

final class ProxyRotatorChecksum {
    private ProxyRotatorChecksum() {}
    static String poolStateHash(ProxyRotatorEngine engine) {
        List<String> parts = new ArrayList<>();
        parts.add("v1");
        parts.add(String.valueOf(engine.endpointCount()));
        parts.add(String.valueOf(engine.regionCount()));
        parts.add(String.valueOf(engine.getTotalRotations()));
        for (String id : engine.getEndpointIds()) {
            ProxySlotDTO s = engine.getEndpoint(id);
            if (s != null) parts.add(id + ":" + s.host + ":" + s.port);
        }
        return ProxyRotatorCore.prxSha256Hex(String.join("|", parts));
    }
    static boolean verifyAddressChecksum(String addr) {
        if (addr == null || !addr.startsWith("0x")) return false;
        String a = addr.substring(2);
        return a.length() == 40 && a.chars().allMatch(c -> Character.digit(c, 16) >= 0);
    }
}

// ============== Time-window stats ==============

final class ProxyRotatorTimeWindowStats {
    private final List<Long> rotationTimestamps = Collections.synchronizedList(new ArrayList<>());
    private final long windowMs;
    private static final int MAX_SAMPLES = 500;

    ProxyRotatorTimeWindowStats(long windowMs) {
        this.windowMs = windowMs;
    }

    public void recordRotation() {
        long now = System.currentTimeMillis();
        rotationTimestamps.add(now);
        while (rotationTimestamps.size() > MAX_SAMPLES) rotationTimestamps.remove(0);
        rotationTimestamps.removeIf(t -> now - t > windowMs);
    }

    public int rotationsInWindow() {
        long now = System.currentTimeMillis();
        rotationTimestamps.removeIf(t -> now - t > windowMs);
        return rotationTimestamps.size();
    }
}

// ============== State export/import ==============

final class ProxyRotatorStateExport {
    private ProxyRotatorStateExport() {}
    static Map<String, Object> exportState(ProxyRotatorEngine engine) {
        Map<String, Object> m = new HashMap<>();
        m.put("hubController", engine.getHubController());
        m.put("cyclerKeeper", engine.getCyclerKeeper());
        m.put("anchorRelay", engine.getAnchorRelay());
        m.put("totalRotations", engine.getTotalRotations());
        m.put("endpoints", ProxyRotatorApiHandlers.listEndpoints(engine, 0, ProxyRotatorCore.PRX_MAX_POOL_SIZE));
        m.put("regions", ProxyRotatorApiHandlers.listRegions(engine));
        m.put("checksum", ProxyRotatorChecksum.poolStateHash(engine));
        return m;
    }
}

// ============== Filter builder ==============

final class ProxyRotatorFilterBuilder {
    private boolean healthyOnly;
    private String regionCode;
    private Integer minPort;
    private Integer maxPort;

    ProxyRotatorFilterBuilder healthyOnly(boolean v) { healthyOnly = v; return this; }
    ProxyRotatorFilterBuilder region(String code) { regionCode = code; return this; }
    ProxyRotatorFilterBuilder portRange(int min, int max) { minPort = min; maxPort = max; return this; }

    List<ProxySlotDTO> apply(ProxyRotatorEngine engine) {
        List<ProxySlotDTO> list = new ArrayList<>();
        for (String id : engine.getEndpointIds()) {
            ProxySlotDTO s = engine.getEndpoint(id);
            if (s == null) continue;
            if (healthyOnly && !s.healthy) continue;
            if (regionCode != null && !regionCode.equals(s.regionCode)) continue;
            if (minPort != null && s.port < minPort) continue;
            if (maxPort != null && s.port > maxPort) continue;
            list.add(s);
        }
        return list;
    }
}

// ============== Stats aggregator ==============

final class ProxyRotatorStatsAggregator {
    private final ProxyRotatorEngine engine;
    private final ProxyRotatorMetrics metrics;

    ProxyRotatorStatsAggregator(ProxyRotatorEngine engine, ProxyRotatorMetrics metrics) {
        this.engine = engine;
        this.metrics = metrics;
    }

    public Map<String, Object> fullReport() {
        Map<String, Object> m = new HashMap<>();
        m.put("rotationStats", ProxyRotatorApiHandlers.getRotationStats(engine));
        m.put("healthSummary", ProxyRotatorApiHandlersExtended.getHealthSummary(engine));
        m.put("poolSummary", ProxyRotatorApiHandlersExtended.getPoolSummary(engine));
        m.put("metrics", metrics.snapshot());
        m.put("checksum", ProxyRotatorChecksum.poolStateHash(engine));
        return m;
    }
}

// ============== Listener / callback interface ==============

interface ProxyRotatorListener {
    void onSlotRotated(ProxySlotDTO previous, ProxySlotDTO current);
    void onEndpointAdded(String endpointId);
    void onEndpointRemoved(String endpointId);
}

final class ProxyRotatorListenerRegistry {
    private static final List<ProxyRotatorListener> listeners = Collections.synchronizedList(new ArrayList<>());

    static void add(ProxyRotatorListener l) { if (l != null) listeners.add(l); }
    static void remove(ProxyRotatorListener l) { listeners.remove(l); }

    static void notifySlotRotated(ProxySlotDTO prev, ProxySlotDTO curr) {
        for (ProxyRotatorListener l : new ArrayList<>(listeners)) {
            try { l.onSlotRotated(prev, curr); } catch (Exception ignored) {}
        }
    }
    static void notifyEndpointAdded(String id) {
        for (ProxyRotatorListener l : new ArrayList<>(listeners)) {
            try { l.onEndpointAdded(id); } catch (Exception ignored) {}
        }
    }
    static void notifyEndpointRemoved(String id) {
        for (ProxyRotatorListener l : new ArrayList<>(listeners)) {
            try { l.onEndpointRemoved(id); } catch (Exception ignored) {}
        }
    }
}

// ============== More region codes ==============

final class ProxyRotatorRegionCodes {
    private ProxyRotatorRegionCodes() {}
    static final String NA_US = "NA-US";
    static final String NA_CA = "NA-CA";
    static final String EU_DE = "EU-DE";
    static final String EU_NL = "EU-NL";
    static final String EU_UK = "EU-UK";
    static final String APAC_SG = "APAC-SG";
    static final String APAC_JP = "APAC-JP";
    static final String APAC_IN = "APAC-IN";
    static final String SA_BR = "SA-BR";
    static final String OC_AU = "OC-AU";
    static final String AF_ZA = "AF-ZA";
    static String[] all() {
        return new String[] { NA_US, NA_CA, EU_DE, EU_NL, EU_UK, APAC_SG, APAC_JP, APAC_IN, SA_BR, OC_AU, AF_ZA };
    }
}

// ============== Slot index helpers ==============

final class ProxyRotatorSlotIndex {
    private ProxyRotatorSlotIndex() {}
    static int currentIndex(ProxyRotatorEngine engine) {
        int size = engine.endpointCount();
        if (size == 0) return -1;
        return (engine.getTotalRotations() % size + size) % size;
    }
    static String endpointIdAt(ProxyRotatorEngine engine, int index) {
        List<String> ids = engine.getEndpointIds();
        if (index < 0 || index >= ids.size()) return null;
        return ids.get(index);
    }
}

// ============== Warmup helper ==============

final class ProxyRotatorWarmup {
    private ProxyRotatorWarmup() {}
    static void warmupPool(ProxyRotatorEngine engine, String hub, int count) {
        for (int i = 0; i < count && engine.endpointCount() < ProxyRotatorCore.PRX_MAX_POOL_SIZE; i++) {
            String epId = ProxyRotatorIdGen.nextEndpointId();
            String region = ProxyRotatorRegionHelper.regionCodeFromIndex(i % ProxyRotatorRegionHelper.DEFAULT_REGION_CODES.length);
            try {
                engine.addEndpoint(epId, "warmup-" + i + ".pool.surf", 8080 + (i % 100), region, hub);
            } catch (Exception ignored) {}
        }
    }
}

// ============== Request context ==============

final class ProxyRotatorRequestContext {
    final String requestId;
    final String preferredRegion;
    final String sessionId;
    final long createdAtMs;

    ProxyRotatorRequestContext(String requestId, String preferredRegion, String sessionId) {
        this.requestId = requestId != null ? requestId : ProxyRotatorCore.prxSha256Hex("req" + System.nanoTime()).substring(0, 16);
        this.preferredRegion = preferredRegion;
        this.sessionId = sessionId;
        this.createdAtMs = System.currentTimeMillis();
    }
}

// ============== Round-trip selector ==============

final class ProxyRotatorRoundTripSelector {
    private final ProxyRotatorEngine engine;
    private final SurfFromAnywhereRouter router;
    private final ProxyRotatorStickySession sticky;

    ProxyRotatorRoundTripSelector(ProxyRotatorEngine engine, long stickyTtlMs) {
        this.engine = engine;
        this.router = new SurfFromAnywhereRouter(engine, ProxyRotatorCore.PRX_ORACLE_RELAY);
        this.sticky = new ProxyRotatorStickySession(stickyTtlMs);
    }

    public ProxySlotDTO select(ProxyRotatorRequestContext ctx) {
        if (ctx.sessionId != null && !ctx.sessionId.isEmpty()) {
            ProxySlotDTO s = sticky.resolve(engine, ctx.sessionId);
            if (s != null) return s;
        }
        if (ctx.preferredRegion != null && !ctx.preferredRegion.isEmpty()) {
            ProxySlotDTO s = router.routeByRegion(ctx.preferredRegion);
            if (s != null) return s;
        }
        return router.routeRoundRobin();
    }
}

// ============== Circuit breaker sim ==============

final class ProxyRotatorCircuitBreaker {
    private final Map<String, Integer> failureCount = new ConcurrentHashMap<>();
    private final int threshold;
    private final long resetWindowMs;

    ProxyRotatorCircuitBreaker(int threshold, long resetWindowMs) {
        this.threshold = threshold;
        this.resetWindowMs = resetWindowMs;
    }

    public void recordSuccess(String endpointId) {
        failureCount.put(endpointId, 0);
    }

    public void recordFailure(String endpointId) {
        failureCount.merge(endpointId, 1, Integer::sum);
    }

    public boolean isOpen(String endpointId) {
        return failureCount.getOrDefault(endpointId, 0) >= threshold;
    }
}

// ============== Load balance strategies ==============

enum ProxyRotatorLBStrategy {
    ROUND_ROBIN,
    RANDOM,
    LEAST_CONNECTIONS,
    REGION_AFFINITY,
    WEIGHTED_REGION
}

final class ProxyRotatorLoadBalancer {
    private final ProxyRotatorEngine engine;
    private final ProxyRotatorRegionWeight regionWeight;
    private final Map<String, AtomicLong> connectionCount = new ConcurrentHashMap<>();

    ProxyRotatorLoadBalancer(ProxyRotatorEngine engine, ProxyRotatorRegionWeight regionWeight) {
        this.engine = engine;
        this.regionWeight = regionWeight;
        for (String id : engine.getEndpointIds()) connectionCount.put(id, new AtomicLong(0));
    }

    public ProxySlotDTO select(ProxyRotatorLBStrategy strategy, String regionCode) {
        switch (strategy) {
            case ROUND_ROBIN:
                engine.rotate(ProxyRotatorCore.PRX_CYCLER_KEEPER);
                return engine.getCurrentSlot();
            case RANDOM:
                return ProxyRotatorEngineViews.getRandomSlot(engine);
            case LEAST_CONNECTIONS:
                return selectLeastConnections();
            case REGION_AFFINITY:
                return new SurfFromAnywhereRouter(engine, ProxyRotatorCore.PRX_ORACLE_RELAY).routeByRegion(regionCode != null ? regionCode : "NA-US");
            case WEIGHTED_REGION:
                return regionWeight.selectByWeight();
            default:
                return engine.getCurrentSlot();
        }
    }

    private ProxySlotDTO selectLeastConnections() {
        List<ProxySlotDTO> healthy = ProxyRotatorEngineViews.getHealthyEndpoints(engine);
        if (healthy.isEmpty()) return engine.getCurrentSlot();
        return healthy.stream()
            .min(Comparator.comparingLong(s -> connectionCount.getOrDefault(s.endpointId, new AtomicLong(0)).get()))
            .orElse(engine.getCurrentSlot());
    }

    public void recordConnection(String endpointId) {
        connectionCount.computeIfAbsent(endpointId, k -> new AtomicLong(0)).incrementAndGet();
    }

    public void recordDisconnect(String endpointId) {
        AtomicLong c = connectionCount.get(endpointId);
        if (c != null && c.get() > 0) c.decrementAndGet();
    }
}

// ============== Hex and address helpers ==============

final class ProxyRotatorHexUtils {
    private ProxyRotatorHexUtils() {}
    static String toHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
    static String addressFromSeed(String seed) {
        String h = ProxyRotatorCore.prxSha256Hex(seed);
        return "0x" + (h.length() >= 40 ? h.substring(0, 40) : h + "0".repeat(40 - h.length()));
    }
}

// ============== Endpoint metadata ==============

final class EndpointMetadataDTO {
    final String endpointId;
    final Map<String, String> tags;
    final long createdAtMs;

    EndpointMetadataDTO(String endpointId, Map<String, String> tags, long createdAtMs) {
        this.endpointId = endpointId;
        this.tags = tags != null ? new HashMap<>(tags) : new HashMap<>();
        this.createdAtMs = createdAtMs;
    }
}

final class ProxyRotatorMetadataStore {
    private final Map<String, EndpointMetadataDTO> store = new ConcurrentHashMap<>();

    void put(String endpointId, Map<String, String> tags) {
        store.put(endpointId, new EndpointMetadataDTO(endpointId, tags, System.currentTimeMillis()));
    }

    EndpointMetadataDTO get(String endpointId) {
        return store.get(endpointId);
    }

    void remove(String endpointId) {
        store.remove(endpointId);
    }
}

// ============== Drain order ==============

final class ProxyRotatorDrainOrder {
    private ProxyRotatorDrainOrder() {}
    static List<String> byRegionThenAge(ProxyRotatorEngine engine) {
        List<String> ids = engine.getEndpointIds();
        List<ProxySlotDTO> slots = new ArrayList<>();
        for (String id : ids) {
            ProxySlotDTO s = engine.getEndpoint(id);
            if (s != null) slots.add(s);
        }
        slots.sort(Comparator.comparing((ProxySlotDTO s) -> s.regionCode).thenComparingLong(s -> s.lastRotatedAt));
        List<String> out = new ArrayList<>();
        for (ProxySlotDTO s : slots) out.add(s.endpointId);
