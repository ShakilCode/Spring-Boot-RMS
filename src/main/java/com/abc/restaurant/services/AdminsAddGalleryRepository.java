package com.abc.restaurant.services;

import org.springframework.data.jpa.repository.JpaRepository;

import com.abc.restaurant.models.AdminAddGallery;
import com.abc.restaurant.models.AdminAddGalleryDto;

                                              // Model name  // Type of the primary key
public interface AdminsAddGalleryRepository extends JpaRepository<AdminAddGallery, Integer> {
    public void save(AdminAddGalleryDto adminAddGalleryDto);
}
