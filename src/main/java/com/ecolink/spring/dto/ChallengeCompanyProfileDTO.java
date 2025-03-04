package com.ecolink.spring.dto;

import java.math.BigDecimal;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ChallengeCompanyProfileDTO {

    String shortDescription;
    BigDecimal budget;
    Integer numberOfParticipans;
}
