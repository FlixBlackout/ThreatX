package com.threatx.dashboard.model;

import jakarta.persistence.*;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Entity representing a threat analysis result
 */
@Entity
@Table(name = "threat_analyses")
@JsonIgnoreProperties(ignoreUnknown = true)
public class ThreatAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "log_entry_id")
    private Long logEntryId;

    @Column(name = "risk_score", nullable = false)
    private Double riskScore;

    @Column(name = "risk_level", nullable = false, length = 20)
    private String riskLevel;

    @Column(name = "model_scores", columnDefinition = "jsonb")
    private String modelScores;

    @ElementCollection
    @CollectionTable(name = "threat_types", joinColumns = @JoinColumn(name = "threat_analysis_id"))
    @Column(name = "threat_type")
    private List<String> threatTypes;

    @ElementCollection
    @CollectionTable(name = "recommendations", joinColumns = @JoinColumn(name = "threat_analysis_id"))
    @Column(name = "recommendation")
    private List<String> recommendations;

    @Column(name = "confidence")
    private Double confidence;

    @Column(name = "analysis_timestamp")
    private LocalDateTime analysisTimestamp;

    // Associated log entry data (not persisted, populated via joins)
    @Transient
    private String ipAddress;

    @Transient
    private String userId;

    @Transient
    private String eventType;

    // Constructors
    public ThreatAnalysis() {
        this.analysisTimestamp = LocalDateTime.now();
    }

    public ThreatAnalysis(Double riskScore, String riskLevel, Double confidence) {
        this();
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.confidence = confidence;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getLogEntryId() {
        return logEntryId;
    }

    public void setLogEntryId(Long logEntryId) {
        this.logEntryId = logEntryId;
    }

    public Double getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(Double riskScore) {
        this.riskScore = riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getModelScores() {
        return modelScores;
    }

    public void setModelScores(String modelScores) {
        this.modelScores = modelScores;
    }

    public List<String> getThreatTypes() {
        return threatTypes;
    }

    public void setThreatTypes(List<String> threatTypes) {
        this.threatTypes = threatTypes;
    }

    public List<String> getRecommendations() {
        return recommendations;
    }

    public void setRecommendations(List<String> recommendations) {
        this.recommendations = recommendations;
    }

    public Double getConfidence() {
        return confidence;
    }

    public void setConfidence(Double confidence) {
        this.confidence = confidence;
    }

    public LocalDateTime getAnalysisTimestamp() {
        return analysisTimestamp;
    }

    public void setAnalysisTimestamp(LocalDateTime analysisTimestamp) {
        this.analysisTimestamp = analysisTimestamp;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    // Utility methods
    public boolean isHighRisk() {
        return "HIGH".equals(riskLevel);
    }

    public boolean isMediumRisk() {
        return "MEDIUM".equals(riskLevel);
    }

    public String getRiskBadgeClass() {
        return switch (riskLevel) {
            case "HIGH" -> "badge-danger";
            case "MEDIUM" -> "badge-warning";
            case "LOW" -> "badge-info";
            default -> "badge-success";
        };
    }

    @Override
    public String toString() {
        return "ThreatAnalysis{" +
                "id=" + id +
                ", riskScore=" + riskScore +
                ", riskLevel='" + riskLevel + '\'' +
                ", confidence=" + confidence +
                ", analysisTimestamp=" + analysisTimestamp +
                '}';
    }
}