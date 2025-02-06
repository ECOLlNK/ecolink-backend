package com.ecolink.spring.dto;

import java.math.BigDecimal;
import java.time.LocalDate;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ProductDTO {
    private Long id;
    private String name;
    private String description;
    private String imageUrl;
    private BigDecimal price;
    private LocalDate creationDate;
    private String startupName;
}