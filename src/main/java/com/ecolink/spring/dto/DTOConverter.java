package com.ecolink.spring.dto;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

import com.ecolink.spring.entity.Challenge;
import com.ecolink.spring.entity.Mission;
import com.ecolink.spring.entity.Ods;
import com.ecolink.spring.entity.Post;
import com.ecolink.spring.entity.Product;
import com.ecolink.spring.entity.Proposal;
import com.ecolink.spring.entity.Startup;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class DTOConverter {

    private final ModelMapper modelMapper;

    public ProductDTO convertProductToDto(Product product) {
        return modelMapper.map(product, ProductDTO.class);
    }

    public ProductRelevantDTO convertProductRelevantToDto(Product product) {
        return modelMapper.map(product, ProductRelevantDTO.class);
    }

    public ProposalDTO convertProposalToDto(Proposal proposal) {
        return modelMapper.map(proposal, ProposalDTO.class);
    }

    public ProposalStartupDTO convertProposalStartupToDto(Proposal proposal) {
        return modelMapper.map(proposal, ProposalStartupDTO.class);
    }

    public StartupDTO convertStartupToDto(Startup startup) {

        StartupDTO startupDto = modelMapper.map(startup, StartupDTO.class);

        startupDto.setOdsList(startup.getOdsList().stream()
                .map(this::convertOdsToDto)
                .collect(Collectors.toList()));
        List<Proposal> proposals = startup.getProposals();

        List<ProposalStartupDTO> proposalsDto = new ArrayList<>();

        proposals.forEach(proposal -> {
            ProposalStartupDTO proposalDto = this.convertProposalStartupToDto(proposal);
            ChallengeDTO challengeDTO = this.converChallengeToDto(proposal.getChallenge());

            proposalDto.setChallenge(challengeDTO);
            proposalsDto.add(proposalDto);
        });

        startupDto.setProposals(proposalsDto);

        return startupDto;
    }

    public StartupHomeDTO convertStartupHomeToDto(Startup startup) {
        return modelMapper.map(startup, StartupHomeDTO.class);
    }

    public PostDTO convertPostToDto(Post post) {
        return modelMapper.map(post, PostDTO.class);
    }

    public MissionDTO convertMissionToDto(Mission mission) {
        return modelMapper.map(mission, MissionDTO.class);
    }

    public ChallengeDTO converChallengeToDto(Challenge challenge) {
        return modelMapper.map(challenge, ChallengeDTO.class);
    }

    public OdsDTO convertOdsToDto(Ods ods) {
        return modelMapper.map(ods, OdsDTO.class);
    }

}