package com.security.network.service;

import org.springframework.stereotype.Service;

@Service
public class BasicSecurityService implements SecurityService {
    @Override
    public String analizarSolicitud(String request) {
        return "La URL ingresada es segura.";
    }
}
