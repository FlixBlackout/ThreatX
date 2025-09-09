package com.threatx.dashboard.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity representing a user's risk profile
 */
@Entity
@Table(name = "user_risk_profiles")
public class UserRiskProfile {

    @Id
    @Column(name = "user_id", length = 255)
    private String userId;

    @Column(name = "current_risk_score")
    private Double currentRiskScore = 0.5;

    @Column(name = "total_alerts")
    private Integer totalAlerts = 0;

    @Column(name = "last_suspicious_activity")
    private LocalDateTime lastSuspiciousActivity;

    @Column(name = "risk_history", columnDefinition = "TEXT")
    private String riskHistory;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // Constructors
    public UserRiskProfile() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    public UserRiskProfile(String userId) {
        this();
        this.userId = userId;
    }

    // Getters and Setters
    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Double getCurrentRiskScore() {
        return currentRiskScore;
    }

    public void setCurrentRiskScore(Double currentRiskScore) {
        this.currentRiskScore = currentRiskScore;
    }

    public Integer getTotalAlerts() {
        return totalAlerts;
    }

    public void setTotalAlerts(Integer totalAlerts) {
        this.totalAlerts = totalAlerts;
    }

    public LocalDateTime getLastSuspiciousActivity() {
        return lastSuspiciousActivity;
    }

    public void setLastSuspiciousActivity(LocalDateTime lastSuspiciousActivity) {
        this.lastSuspiciousActivity = lastSuspiciousActivity;
    }

    public String getRiskHistory() {
        return riskHistory;
    }

    public void setRiskHistory(String riskHistory) {
        this.riskHistory = riskHistory;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    // Utility methods
    public String getRiskLevel() {
        if (currentRiskScore >= 0.8) return "HIGH";
        if (currentRiskScore >= 0.6) return "MEDIUM";
        if (currentRiskScore >= 0.3) return "LOW";
        return "NORMAL";
    }

    public String getRiskBadgeClass() {
        return switch (getRiskLevel()) {
            case "HIGH" -> "badge-danger";
            case "MEDIUM" -> "badge-warning";
            case "LOW" -> "badge-info";
            default -> "badge-success";
        };
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    @Override
    public String toString() {
        return "UserRiskProfile{" +
                "userId='" + userId + '\'' +
                ", currentRiskScore=" + currentRiskScore +
                ", totalAlerts=" + totalAlerts +
                ", lastSuspiciousActivity=" + lastSuspiciousActivity +
                '}';
    }
}