package com.example.ecolink.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.ecolink.ecolink.repository.ClientRepository;

@Service
public class ClientService {
    @Autowired
    private ClientRepository repository;
    
}
