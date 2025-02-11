package com.ecolink.spring.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class StartupProfileDTO {

    String imageStartup;
    String status;
    String name;
    String description;
    List<OdsWithoutIdDTO> odsList;
    List<ProposalStartupProfileDTO> proposals;
    List<StartupProductProfileDTO> products;
    List<PostProfileUserDTO> listLikePost;
}
