package com.security.network.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

@Service
public class SafeBrowsingService {

    @Value("${google.safebrowsing.api_key}")
    private String apiKey;

    private static final String SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=";

    public boolean esMaliciosa(String url) {
        RestTemplate restTemplate = new RestTemplate();

        JsonObject requestBody = new JsonObject();
        JsonObject client = new JsonObject();
        client.addProperty("clientId", "tu-aplicacion");
        client.addProperty("clientVersion", "1.0");

        JsonObject threatInfo = new JsonObject();
        threatInfo.add("threatTypes", crearJsonArray("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"));
        threatInfo.add("platformTypes", crearJsonArray("ANY_PLATFORM"));
        threatInfo.add("threatEntryTypes", crearJsonArray("URL"));

        JsonArray threatEntries = new JsonArray();
        JsonObject threat = new JsonObject();
        threat.addProperty("url", url);
        threatEntries.add(threat);
        threatInfo.add("threatEntries", threatEntries);

        requestBody.add("client", client);
        requestBody.add("threatInfo", threatInfo);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> entity = new HttpEntity<>(requestBody.toString(), headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                SAFE_BROWSING_URL + apiKey,
                HttpMethod.POST,
                entity,
                String.class
            );

            JsonObject jsonResponse = JsonParser.parseString(response.getBody()).getAsJsonObject();
            return jsonResponse.has("matches");

        } catch (IllegalArgumentException | NullPointerException ex) {
            // Puedes personalizar el manejo de errores aquí
            System.err.println("⚠️ Error al consultar Google Safe Browsing: " + ex.getMessage());
            return false;
        }
    }

    private JsonArray crearJsonArray(String... valores) {
        JsonArray jsonArray = new JsonArray();
        for (String valor : valores) {
            jsonArray.add(valor);
        }
        return jsonArray;
    }
}
