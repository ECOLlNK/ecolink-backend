package com.ecolink.spring.dto;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

import com.ecolink.spring.entity.Ods;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ChallengeFindDTO {
    private Long id;
    private String title;
    private String description;
    private BigDecimal budget;
    private LocalDateTime startDate;
    private LocalDateTime endDate;
    private CompanyForChallengeDTO company;
    List<String> requirements;
    List<String> benefits;
    private Integer numberOfParticipans;
    List<Ods> odsList;
}
