package com.threatx.dashboard.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity representing a threat type associated with a threat analysis
 */
@Entity
@Table(name = "threat_types")
public class ThreatType {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "threat_analysis_id")
    private Long threatAnalysisId;

    @Column(name = "threat_type")
    private String threatType;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    // Constructors
    public ThreatType() {
        this.createdAt = LocalDateTime.now();
    }

    public ThreatType(Long threatAnalysisId, String threatType) {
        this();
        this.threatAnalysisId = threatAnalysisId;
        this.threatType = threatType;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getThreatAnalysisId() {
        return threatAnalysisId;
    }

    public void setThreatAnalysisId(Long threatAnalysisId) {
        this.threatAnalysisId = threatAnalysisId;
    }

    public String getThreatType() {
        return threatType;
    }

    public void setThreatType(String threatType) {
        this.threatType = threatType;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String toString() {
        return "ThreatType{" +
                "id=" + id +
                ", threatAnalysisId=" + threatAnalysisId +
                ", threatType='" + threatType + '\'' +
                ", createdAt=" + createdAt +
                '}';
    }
}