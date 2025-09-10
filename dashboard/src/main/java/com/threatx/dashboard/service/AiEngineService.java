package com.threatx.dashboard.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Service for communicating with the AI Engine API
 */
@Service
public class AiEngineService {

    private static final Logger logger = LoggerFactory.getLogger(AiEngineService.class);

    private final WebClient webClient;

    @Value("${threatx.ai-engine.base-url}")
    private String aiEngineBaseUrl;

    @Value("${threatx.ai-engine.timeout:30000}")
    private long timeout;

    public AiEngineService(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(1024 * 1024))
                .build();
    }

    /**
     * Detect threats in log data
     */
    public Mono<Map<String, Object>> detectThreat(Map<String, Object> logData) {
        logger.debug("Sending threat detection request for log data: {}", logData);

        return webClient.post()
                .uri(buildUri("/api/detect-threat"))
                .bodyValue(logData)
                .retrieve()
                .bodyToMono(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {})
                .timeout(Duration.ofMillis(timeout))
                .doOnSuccess(result -> logger.debug("Threat detection response: {}", result))
                .doOnError(error -> logger.error("Error detecting threat: {}", error.getMessage()))
                .onErrorResume(this::handleWebClientError);
    }

    /**
     * Get user risk profile
     */
    public Mono<Map<String, Object>> getUserRiskProfile(String userId) {
        logger.debug("Getting user risk profile for: {}", userId);

        return webClient.get()
                .uri(buildUri("/api/user-risk-profile/{userId}"), userId)
                .retrieve()
                .bodyToMono(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {})
                .timeout(Duration.ofMillis(timeout))
                .doOnSuccess(result -> logger.debug("User risk profile response: {}", result))
                .doOnError(error -> logger.error("Error getting user risk profile: {}", error.getMessage()))
                .onErrorResume(this::handleWebClientError);
    }

    /**
     * Get threat statistics
     */
    public Mono<Map<String, Object>> getThreatStatistics(String timeRange) {
        logger.debug("Getting threat statistics for time range: {}", timeRange);
        
        return webClient.get()
                .uri(buildUri("/api/threat-statistics?range={timeRange}&format=json"), timeRange)
                .retrieve()
                .bodyToMono(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {})
                .timeout(Duration.ofMillis(timeout))
                .doOnSuccess(result -> {
                    logger.debug("Threat statistics response: {}", result);
                    if (result != null) {
                        logger.debug("Response keys: {}", result.keySet());
                    }
                })
                .doOnError(error -> {
                    logger.error("Error getting threat statistics: {}", error.getMessage(), error);
                    if (error instanceof java.util.concurrent.TimeoutException) {
                        logger.error("Timeout occurred while getting threat statistics");
                    } else if (error instanceof org.springframework.web.reactive.function.client.WebClientRequestException) {
                        logger.error("WebClient request exception: {}", error.getMessage());
                    } else if (error instanceof org.springframework.web.reactive.function.client.WebClientResponseException) {
                        WebClientResponseException wcre = (WebClientResponseException) error;
                        logger.error("WebClient response exception - Status: {}, Response: {}", 
                            wcre.getStatusCode(), wcre.getResponseBodyAsString());
                    } else {
                        logger.error("Unexpected error type: {}", error.getClass().getName());
                    }
                })
                .onErrorResume(this::handleWebClientError);
    }

    /**
     * Get suspicious IPs
     */
    public Mono<List<Map<String, Object>>> getSuspiciousIps(int limit) {
        logger.debug("Getting suspicious IPs with limit: {}", limit);

        return webClient.get()
                .uri(buildUri("/api/suspicious-ips?limit={limit}"), limit)
                .retrieve()
                .bodyToMono(new org.springframework.core.ParameterizedTypeReference<List<Map<String, Object>>>() {})
                .timeout(Duration.ofMillis(timeout))
                .onErrorResume(error -> {
                    logger.error("Error getting suspicious IPs: {}", error.getMessage(), error);
                    return Mono.just(new ArrayList<>());
                })
                .doOnSuccess(result -> logger.debug("Suspicious IPs response size: {}", 
                        result != null ? result.size() : 0))
                .doOnError(error -> {
                    logger.error("Error getting suspicious IPs: {}", error.getMessage());
                    if (error instanceof WebClientResponseException) {
                        WebClientResponseException wcre = (WebClientResponseException) error;
                        logger.error("Response status: {}", wcre.getStatusCode());
                        logger.error("Response body: {}", wcre.getResponseBodyAsString());
                    }
                });
    }

    /**
     * Trigger model retraining
     */
    public Mono<Map<String, Object>> retrainModels() {
        logger.info("Triggering model retraining");

        return webClient.post()
                .uri(buildUri("/api/retrain-models"))
                .retrieve()
                .bodyToMono(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {})
                .timeout(Duration.ofMillis(timeout * 2)) // Longer timeout for retraining
                .doOnSuccess(result -> logger.info("Model retraining response: {}", result))
                .doOnError(error -> logger.error("Error retraining models: {}", error.getMessage()))
                .onErrorResume(this::handleWebClientError);
    }

    /**
     * Check AI Engine health
     */
    public Mono<Map<String, Object>> checkHealth() {
        logger.debug("Checking AI Engine health");

        return webClient.get()
                .uri(buildUri("/health?format=json"))
                .retrieve()
                .bodyToMono(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {})
                .timeout(Duration.ofMillis(5000)) // Short timeout for health check
                .doOnSuccess(result -> logger.debug("AI Engine health check response: {}", result))
                .doOnError(error -> {
                    logger.warn("AI Engine health check failed: {}", error.getMessage());
                    if (error instanceof WebClientResponseException) {
                        WebClientResponseException wcre = (WebClientResponseException) error;
                        logger.error("Response status: {}", wcre.getStatusCode());
                        logger.error("Response body: {}", wcre.getResponseBodyAsString());
                    }
                })
                .onErrorResume(this::handleWebClientError);
    }

    /**
     * Submit log data for batch processing
     */
    public Mono<Map<String, Object>> submitLogBatch(List<Map<String, Object>> logBatch) {
        logger.debug("Submitting log batch with {} entries", logBatch.size());

        Map<String, Object> request = new HashMap<>();
        request.put("logs", logBatch);

        return webClient.post()
                .uri(buildUri("/api/analyze-batch"))
                .bodyValue(request)
                .retrieve()
                .bodyToMono(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {})
                .timeout(Duration.ofMillis(timeout * 2)) // Longer timeout for batch processing
                .doOnSuccess(result -> logger.debug("Batch processing response: {}", result))
                .doOnError(error -> logger.error("Error processing log batch: {}", error.getMessage()))
                .onErrorResume(this::handleWebClientError);
    }

    /**
     * Get model performance metrics
     */
    public Mono<Map<String, Object>> getModelMetrics() {
        logger.debug("Getting model performance metrics");

        return webClient.get()
                .uri(buildUri("/api/model-metrics"))
                .retrieve()
                .bodyToMono(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {})
                .timeout(Duration.ofMillis(timeout))
                .doOnSuccess(result -> logger.debug("Model metrics response: {}", result))
                .doOnError(error -> logger.error("Error getting model metrics: {}", error.getMessage()))
                .onErrorResume(this::handleWebClientError);
    }

    /**
     * Test connection to AI Engine
     */
    public boolean isAiEngineAvailable() {
        try {
            Map<String, Object> health = checkHealth().block(Duration.ofSeconds(5));
            // Check for both "healthy" status and absence of error status
            return health != null && 
                   (health.get("status") != null && 
                    (health.get("status").equals("healthy") || !health.get("status").equals("error")));
        } catch (Exception e) {
            logger.warn("AI Engine availability check failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Handle WebClient exceptions and convert to meaningful error messages for Map responses
     */
    private Mono<Map<String, Object>> handleWebClientError(Throwable error) {
        if (error instanceof WebClientResponseException) {
            WebClientResponseException wcre = (WebClientResponseException) error;
            logger.error("AI Engine API error: {} - {}", wcre.getStatusCode(), wcre.getResponseBodyAsString());
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "AI Engine API error");
            errorResponse.put("status_code", wcre.getStatusCode().value());
            errorResponse.put("message", wcre.getResponseBodyAsString());
            
            return Mono.just(errorResponse);
        } else {
            logger.error("Unexpected error communicating with AI Engine", error);
            return Mono.just(createErrorResponse("Unexpected error: " + error.getMessage()));
        }
    }

    /**
     * Create standardized error response
     */
    private Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> error = new HashMap<>();
        error.put("error", message);
        error.put("status", "error");
        error.put("timestamp", System.currentTimeMillis());
        return error;
    }

    /**
     * Build URI with proper path concatenation
     */
    private String buildUri(String path, Object... uriVariables) {
        // Ensure base URL doesn't end with slash and path starts with slash
        String baseUrl = aiEngineBaseUrl;
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        
        String uri = baseUrl + path;
        logger.debug("Built URI: {} with variables: {}", uri, uriVariables);
        return uri;
    }
}