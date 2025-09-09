package com.threatx.dashboard.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity representing a recommendation associated with a threat analysis
 */
@Entity
@Table(name = "recommendations")
public class Recommendation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "threat_analysis_id")
    private Long threatAnalysisId;

    @Column(name = "recommendation")
    private String recommendation;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    // Constructors
    public Recommendation() {
        this.createdAt = LocalDateTime.now();
    }

    public Recommendation(Long threatAnalysisId, String recommendation) {
        this();
        this.threatAnalysisId = threatAnalysisId;
        this.recommendation = recommendation;
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

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String toString() {
        return "Recommendation{" +
                "id=" + id +
                ", threatAnalysisId=" + threatAnalysisId +
                ", recommendation='" + recommendation + '\'' +
                ", createdAt=" + createdAt +
                '}';
    }
}