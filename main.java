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
