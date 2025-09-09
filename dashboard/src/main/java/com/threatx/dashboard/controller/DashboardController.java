package com.threatx.dashboard.controller;

import com.threatx.dashboard.service.AiEngineService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Main dashboard controller
 */
@Controller
public class DashboardController {

    private static final Logger logger = LoggerFactory.getLogger(DashboardController.class);

    @Autowired
    private AiEngineService aiEngineService;

    /**
     * Main dashboard page
     */
    @GetMapping("/")
    public String dashboard(Model model) {
        logger.info("Loading main dashboard");

        try {
            // Check AI Engine status
            boolean aiEngineOnline = aiEngineService.isAiEngineAvailable();
            model.addAttribute("aiEngineOnline", aiEngineOnline);

            if (aiEngineOnline) {
                // Get threat statistics for the last 24 hours
                Map<String, Object> stats = aiEngineService.getThreatStatistics("24h").block();
                model.addAttribute("threatStats", stats);

                // Get recent suspicious IPs
                List<Map<String, Object>> suspiciousIps = aiEngineService.getSuspiciousIps(10).block();
                model.addAttribute("suspiciousIps", suspiciousIps);
            } else {
                logger.warn("AI Engine is not available");
                model.addAttribute("alertMessage", "AI Engine is currently offline. Some features may not be available.");
                model.addAttribute("alertType", "warning");
            }

            // Add current timestamp
            model.addAttribute("currentTime", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));

        } catch (Exception e) {
            logger.error("Error loading dashboard data", e);
            model.addAttribute("alertMessage", "Error loading dashboard data: " + e.getMessage());
            model.addAttribute("alertType", "danger");
        }

        return "dashboard/index";
    }

    /**
     * Real-time monitoring page
     */
    @GetMapping("/monitoring")
    public String monitoring(Model model) {
        logger.info("Loading monitoring page");

        model.addAttribute("pageTitle", "Real-time Monitoring");
        model.addAttribute("aiEngineOnline", aiEngineService.isAiEngineAvailable());

        return "dashboard/monitoring";
    }

    /**
     * Threat analysis page
     */
    @GetMapping("/threats")
    public String threats(
            @RequestParam(defaultValue = "24h") String timeRange,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size,
            Model model) {
        
        logger.info("Loading threats page with timeRange: {}, page: {}, size: {}", timeRange, page, size);

        try {
            // Get threat statistics
            Map<String, Object> stats = aiEngineService.getThreatStatistics(timeRange).block();
            model.addAttribute("threatStats", stats);
            model.addAttribute("timeRange", timeRange);

            // Calculate pagination info
            int totalThreats = stats != null ? (Integer) stats.getOrDefault("total_threats", 0) : 0;
            int totalPages = (int) Math.ceil((double) totalThreats / size);
            
            model.addAttribute("currentPage", page);
            model.addAttribute("totalPages", totalPages);
            model.addAttribute("pageSize", size);

        } catch (Exception e) {
            logger.error("Error loading threats data", e);
            model.addAttribute("alertMessage", "Error loading threats data: " + e.getMessage());
            model.addAttribute("alertType", "danger");
        }

        return "dashboard/threats";
    }

    /**
     * User risk profiles page
     */
    @GetMapping("/users")
    public String users(Model model) {
        logger.info("Loading users page");

        model.addAttribute("pageTitle", "User Risk Profiles");
        model.addAttribute("aiEngineOnline", aiEngineService.isAiEngineAvailable());

        return "dashboard/users";
    }

    /**
     * IP analysis page
     */
    @GetMapping("/ips")
    public String ips(
            @RequestParam(defaultValue = "50") int limit,
            Model model) {
        
        logger.info("Loading IPs page with limit: {}", limit);

        try {
            List<Map<String, Object>> suspiciousIps = aiEngineService.getSuspiciousIps(limit).block();
            model.addAttribute("suspiciousIps", suspiciousIps);
            model.addAttribute("limit", limit);

        } catch (Exception e) {
            logger.error("Error loading IP data", e);
            model.addAttribute("alertMessage", "Error loading IP data: " + e.getMessage());
            model.addAttribute("alertType", "danger");
        }

        return "dashboard/ips";
    }

    /**
     * Settings page
     */
    @GetMapping("/settings")
    public String settings(Model model) {
        logger.info("Loading settings page");

        model.addAttribute("pageTitle", "Settings");
        model.addAttribute("aiEngineOnline", aiEngineService.isAiEngineAvailable());

        return "dashboard/settings";
    }

    /**
     * Test threat detection with sample data
     */
    @PostMapping("/test-detection")
    @ResponseBody
    public Map<String, Object> testDetection(@RequestBody Map<String, Object> testData) {
        logger.info("Testing threat detection with data: {}", testData);

        try {
            // Add timestamp if not present
            if (!testData.containsKey("timestamp")) {
                testData.put("timestamp", LocalDateTime.now().toString());
            }

            // Send to AI engine for analysis
            Map<String, Object> result = aiEngineService.detectThreat(testData).block();
            logger.info("Threat detection result: {}", result);

            return result;

        } catch (Exception e) {
            logger.error("Error in test detection", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Test detection failed: " + e.getMessage());
            errorResponse.put("status", "error");
            return errorResponse;
        }
    }

    /**
     * Get user risk profile via AJAX
     */
    @GetMapping("/api/user-profile/{userId}")
    @ResponseBody
    public Map<String, Object> getUserProfile(@PathVariable String userId) {
        logger.info("Getting user profile for: {}", userId);

        try {
            return aiEngineService.getUserRiskProfile(userId).block();
        } catch (Exception e) {
            logger.error("Error getting user profile", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to get user profile: " + e.getMessage());
            return errorResponse;
        }
    }

    /**
     * Get threat statistics via AJAX
     */
    @GetMapping("/api/threat-statistics")
    @ResponseBody
    public Map<String, Object> getThreatStats(
            @RequestParam(defaultValue = "24h") String timeRange) {
        
        logger.info("Getting threat statistics for timeRange: {}", timeRange);

        try {
            return aiEngineService.getThreatStatistics(timeRange).block();
        } catch (Exception e) {
            logger.error("Error getting threat statistics", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to get threat statistics: " + e.getMessage());
            return errorResponse;
        }
    }

    /**
     * Get suspicious IPs via AJAX
     */
    @GetMapping("/api/suspicious-ips")
    @ResponseBody
    public List<Map<String, Object>> getSuspiciousIps(
            @RequestParam(defaultValue = "10") int limit) {
        
        logger.info("Getting suspicious IPs with limit: {}", limit);

        try {
            return aiEngineService.getSuspiciousIps(limit).block();
        } catch (Exception e) {
            logger.error("Error getting suspicious IPs", e);
            return new ArrayList<>();
        }
    }

    /**
     * Trigger model retraining
     */
    @PostMapping("/retrain-models")
    public String retrainModels(RedirectAttributes redirectAttributes) {
        logger.info("Triggering model retraining");

        try {
            Map<String, Object> result = aiEngineService.retrainModels().block();
            
            if ("success".equals(result.get("status"))) {
                redirectAttributes.addFlashAttribute("successMessage", "Model retraining initiated successfully");
            } else {
                redirectAttributes.addFlashAttribute("errorMessage", "Failed to initiate model retraining");
            }

        } catch (Exception e) {
            logger.error("Error triggering model retraining", e);
            redirectAttributes.addFlashAttribute("errorMessage", "Error triggering model retraining: " + e.getMessage());
        }

        return "redirect:/settings";
    }

    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    @ResponseBody
    public Map<String, Object> health() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "healthy");
        health.put("timestamp", LocalDateTime.now().toString());
        health.put("aiEngine", aiEngineService.isAiEngineAvailable() ? "online" : "offline");
        return health;
    }

    /**
     * Export threats data
     */
    @GetMapping("/export/threats")
    public String exportThreats(
            @RequestParam(defaultValue = "24h") String timeRange,
            @RequestParam(defaultValue = "csv") String format,
            RedirectAttributes redirectAttributes) {
        
        logger.info("Exporting threats data for timeRange: {}, format: {}", timeRange, format);

        try {
            // This would generate a downloadable file
            // For now, just show a success message
            redirectAttributes.addFlashAttribute("successMessage", 
                "Export request submitted for " + timeRange + " data in " + format.toUpperCase() + " format");

        } catch (Exception e) {
            logger.error("Error exporting threats data", e);
            redirectAttributes.addFlashAttribute("errorMessage", "Error exporting data: " + e.getMessage());
        }

        return "redirect:/threats";
    }
}