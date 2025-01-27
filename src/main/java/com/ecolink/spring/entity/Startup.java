package com.ecolink.spring.entity;

import java.util.List;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;

@Entity
public class Startup extends UserBase {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;
    
    @OneToMany(mappedBy = "startup")
    List<Proposal> proposals;
    
    @OneToMany(mappedBy = "startup")
    List<Product> products;

    @ManyToMany
    @JoinTable(name="startup_ods",
    joinColumns = @JoinColumn(name="id_startup"),
    inverseJoinColumns = @JoinColumn(name= "id_ods")
    )
    private List<Ods> odsList;

    
    
    public void addChallenge(Proposal proposal) {
    	this.proposals.add(proposal);
    }
    
    public void addProduct(Product product) {
    	this.products.add(product);
    }

    public void addOds(Ods ods){
        this.odsList.add(ods);
    }
    
}
