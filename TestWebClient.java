import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.core.ParameterizedTypeReference;
import reactor.core.publisher.Mono;

import java.util.Map;

public class TestWebClient {
    public static void main(String[] args) {
        // Test the WebClient configuration
        WebClient webClient = WebClient.builder()
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(1024 * 1024))
                .build();
        
        String baseUrl = "http://localhost:5000";
        String path = "/api/threat-statistics";
        String uri = baseUrl + path;
        
        System.out.println("Testing URI: " + uri);
        
        try {
            Mono<Map<String, Object>> response = webClient.get()
                    .uri(uriBuilder -> uriBuilder
                        .path(uri)
                        .queryParam("format", "json")
                        .build())
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {});
            
            Map<String, Object> result = response.block();
            System.out.println("Response: " + result);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}