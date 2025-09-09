package com.threatx.dashboard.controller;

import com.threatx.dashboard.service.AiEngineService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * REST API Controller for ThreatX Dashboard
 * Provides API endpoints for frontend and external integrations
 */
@RestController
@RequestMapping("/api/ai-engine")
public class ApiController {

    private static final Logger logger = LoggerFactory.getLogger(ApiController.class);

    @Autowired
    private AiEngineService aiEngineService;

    /**
     * Get suspicious IPs from AI Engine
     */
    @GetMapping("/suspicious-ips")
    public ResponseEntity<?> getSuspiciousIps(
            @RequestParam(defaultValue = "10") int limit) {
        
        logger.info("API request for suspicious IPs with limit: {}", limit);
        
        try {
            List<Map<String, Object>> suspiciousIps = aiEngineService.getSuspiciousIps(limit).block();
            return ResponseEntity.ok(suspiciousIps);
        } catch (Exception e) {
            logger.error("Error getting suspicious IPs", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to get suspicious IPs: " + e.getMessage());
            errorResponse.put("status", "error");
            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    /**
     * Check AI Engine health status
     */
    @GetMapping("/health")
    public ResponseEntity<?> getAiEngineHealth() {
        logger.info("API request for AI Engine health");
        
        try {
            Map<String, Object> healthStatus = aiEngineService.checkHealth().block();
            return ResponseEntity.ok(healthStatus);
        } catch (Exception e) {
            logger.error("Error checking AI Engine health", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to check AI Engine health: " + e.getMessage());
            errorResponse.put("status", "error");
            return ResponseEntity.status(500).body(errorResponse);
        }
    }
}