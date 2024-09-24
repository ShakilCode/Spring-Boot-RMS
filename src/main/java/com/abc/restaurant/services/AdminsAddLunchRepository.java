package com.abc.restaurant.services;

import org.springframework.data.jpa.repository.JpaRepository;

import com.abc.restaurant.models.AdminAddLunch;
import com.abc.restaurant.models.AdminAddLunchDto;

                                              // Model name  // Type of the primary key
public interface AdminsAddLunchRepository extends JpaRepository<AdminAddLunch, Integer> {

    public void save(AdminAddLunchDto adminAddLunchDto);
    
}
