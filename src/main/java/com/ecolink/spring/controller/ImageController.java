package com.ecolink.spring.controller;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ecolink.spring.exception.ImageGetExcepcion;

import lombok.RequiredArgsConstructor;

@RequestMapping("/api/image")
@RequiredArgsConstructor
@RestController
public class ImageController {

    @Value("${spring.users.upload.dir}")
    private String uploadUserDir;
    @Value("${spring.ods.upload.dir}")
    private String uploadOdsDir;
    @Value("${spring.products.upload.dir}")
    private String uploadProductDir;

    @GetMapping
    public ResponseEntity<?> findImage(@RequestParam String type, @RequestParam String name_image) {
        try {
            String baseDir = System.getProperty("user.dir");
            String full_url = "";

            switch (type) {
                case "user":
                    full_url = Paths.get(baseDir, uploadUserDir, name_image).toString();
                    break;
                case "ods":
                    full_url = Paths.get(baseDir, uploadOdsDir, name_image).toString();
                    break;
                case "product":
                    full_url = Paths.get(baseDir, uploadProductDir, name_image).toString();
                    break;
            }

            File imageFile = new File(full_url);
            if (!imageFile.exists() || !imageFile.canRead()) {
                throw new ImageGetExcepcion("The image does not exist or cannot be read");
            }

            byte[] imageBytes = Files.readAllBytes(imageFile.toPath());
            String mimeType = Files.probeContentType(imageFile.toPath());

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, mimeType)
                    .body(imageBytes);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al obtener la imagen: " + e.getMessage());
        }
    }

}
