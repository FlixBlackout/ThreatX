package com.threatx.dashboard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main application class for ThreatX Security Dashboard
 */
@SpringBootApplication
@EnableScheduling
public class ThreatXDashboardApplication {

    public static void main(String[] args) {
        SpringApplication.run(ThreatXDashboardApplication.class, args);
    }
}