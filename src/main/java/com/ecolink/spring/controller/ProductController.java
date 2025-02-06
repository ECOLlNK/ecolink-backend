package com.ecolink.spring.controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.ecolink.spring.dto.ProductDTO;
import com.ecolink.spring.dto.ProductPostDTO;
import com.ecolink.spring.dto.ProductRelevantDTO;
import com.ecolink.spring.dto.DTOConverter;
import com.ecolink.spring.dto.PaginationResponse;
import com.ecolink.spring.entity.Product;
import com.ecolink.spring.entity.Startup;
import com.ecolink.spring.entity.UserBase;
import com.ecolink.spring.exception.ErrorDetails;
import com.ecolink.spring.exception.ImageNotValidExtension;
import com.ecolink.spring.exception.ImageSubmitError;
import com.ecolink.spring.exception.ProductNotFoundException;
import com.ecolink.spring.service.ProductService;
import com.ecolink.spring.service.StartupService;
import com.ecolink.spring.utils.Images;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/product")
public class ProductController {
    private final DTOConverter dtoConverter;
    private final ProductService service;
    private final StartupService startupService;
    private final Images images;

    @Value("${spring.products.upload.dir}")
    private String uploadProductDir;

    @GetMapping()
    public ResponseEntity<?> getProducts(
            @RequestParam(required = false) Long startup,
            @RequestParam(required = false) String name,
            @RequestParam(required = false) BigDecimal pricemin,
            @RequestParam(required = false) BigDecimal pricemax,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "8") int size) {

        try {
            Page<Product> products = service.findByPaginationAndFilter(startup, name, pricemin, pricemax, page, size);

            if (products.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorDetails(HttpStatus.NOT_FOUND.value(),
                        "No se encontraron productos en la página especificada"));
            }

            List<ProductDTO> dtoList = products.stream().map(dtoConverter::convertProductToDto)
                    .collect(Collectors.toList());

            var response = new PaginationResponse<>(
                    dtoList,
                    products.getNumber(),
                    products.getSize(),
                    products.getTotalElements(),
                    products.getTotalPages(),
                    products.isLast());

            return ResponseEntity.ok(response);
        } catch (ProductNotFoundException e) {
            ErrorDetails errorDetails = new ErrorDetails(HttpStatus.NOT_FOUND.value(), e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorDetails);
        } catch (Exception e) {
            ErrorDetails errorDetails = new ErrorDetails(HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Ocurrió un error interno en el servidor");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorDetails);
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getProduct(@PathVariable Long id) {
        try {
            Product product = service.findById(id);
            if (product == null) {
                throw new ProductNotFoundException("No existe un producto con id=" + id);
            }
            ProductDTO dto = dtoConverter.convertProductToDto(product);

            return ResponseEntity.ok(dto);
        } catch (ProductNotFoundException e) {
            ErrorDetails errorDetails = new ErrorDetails(HttpStatus.NOT_FOUND.value(), e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorDetails);
        } catch (Exception e) {
            ErrorDetails errorDetails = new ErrorDetails(HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Ocurrió un error interno en el servidor");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorDetails);
        }
    }

    @GetMapping("/relevant")
    public ResponseEntity<?> getRelevantProducts() {
        List<Product> products = service.findTop4ByOrderByCreationDateDesc();
        if (products.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorDetails(HttpStatus.NOT_FOUND.value(), "No se encontraron productos relevantes"));
        }
        List<ProductRelevantDTO> dtoList = products.stream().map(dtoConverter::convertProductRelevantToDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(dtoList);
    }

    // Subir producto Startup

    @Transactional
    @PostMapping("/new")
    public ResponseEntity<?> createProduct(@AuthenticationPrincipal UserBase user,
            @RequestPart("product") String productJson, @RequestPart("image") MultipartFile image) {
                String urlImage = null;
        try {
            if (user instanceof Startup startup) {
                ObjectMapper objectMapper = new ObjectMapper();
                ProductPostDTO product = objectMapper.readValue(productJson, ProductPostDTO.class);
                if (product.getName() == null || product.getName().isEmpty() || product.getPrice() == null
                        || product.getPrice().compareTo(BigDecimal.ZERO) <= 0 || product.getDescription() == null
                        || product.getDescription().isEmpty() || image == null || image.isEmpty()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ErrorDetails(HttpStatus.BAD_REQUEST.value(), "Invalid Fields"));
                }

                Product newProduct = new Product(startup, product.getName(), product.getDescription(),
                        product.getPrice(), LocalDate.now());

                if (!images.isExtensionImageValid(image)) {
                    throw new ImageNotValidExtension("The extension is invalid");
                }
                urlImage = images.uploadFile(image, uploadProductDir);
                if (urlImage == null || urlImage.isEmpty()) {
                    throw new ImageSubmitError("Error to submit the image");
                }
                
                newProduct.setImageUrl(urlImage);

                service.save(newProduct);
                startup.addProduct(newProduct);
                startupService.save(startup);
                return ResponseEntity.ok(product);
            }
            throw new UsernameNotFoundException("User not permissions");
        } catch (Exception e) {
            ErrorDetails errorDetails = new ErrorDetails(HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Internal Error Server");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorDetails);
        }
    }

    // Editar producto Startup

    // Eliminar producto Startup y Admin

}