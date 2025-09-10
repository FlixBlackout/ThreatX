package com.threatx.dashboard.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity representing a suspicious IP address
 */
@Entity
@Table(name = "suspicious_ips")
public class SuspiciousIp {

    @Id
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "reputation_score")
    private Double reputationScore = 0.5;

    @Column(name = "threat_count")
    private Integer threatCount = 0;

    @Column(name = "last_threat_time")
    private LocalDateTime lastThreatTime;

    @Column(name = "country_code", length = 2)
    private String countryCode;

    @Column(name = "is_blocked")
    private Boolean isBlocked = false;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // Constructors
    public SuspiciousIp() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    public SuspiciousIp(String ipAddress) {
        this();
        this.ipAddress = ipAddress;
    }

    // Getters and Setters
    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public Double getReputationScore() {
        return reputationScore;
    }

    public void setReputationScore(Double reputationScore) {
        this.reputationScore = reputationScore;
    }

    public Integer getThreatCount() {
        return threatCount;
    }

    public void setThreatCount(Integer threatCount) {
        this.threatCount = threatCount;
    }

    public LocalDateTime getLastThreatTime() {
        return lastThreatTime;
    }

    public void setLastThreatTime(LocalDateTime lastThreatTime) {
        this.lastThreatTime = lastThreatTime;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }

    public Boolean getIsBlocked() {
        return isBlocked;
    }

    public void setIsBlocked(Boolean isBlocked) {
        this.isBlocked = isBlocked;
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
    public String getThreatLevel() {
        if (reputationScore <= 0.2) return "HIGH";
        if (reputationScore <= 0.4) return "MEDIUM";
        if (reputationScore <= 0.6) return "LOW";
        return "NORMAL";
    }

    public String getThreatBadgeClass() {
        return switch (getThreatLevel()) {
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
        return "SuspiciousIp{" +
                "ipAddress='" + ipAddress + '\'' +
                ", reputationScore=" + reputationScore +
                ", threatCount=" + threatCount +
                ", lastThreatTime=" + lastThreatTime +
                ", countryCode='" + countryCode + '\'' +
                ", isBlocked=" + isBlocked +
                '}';
    }
}