package com.abc.restaurant.models;

import org.springframework.web.multipart.MultipartFile;

public class AdminAddGalleryDto {

    private MultipartFile imageFile;

    public MultipartFile getImageFile() {
        return imageFile;
    }
    public void setImageFile(MultipartFile imageFile) {
        this.imageFile = imageFile;
    }

}
