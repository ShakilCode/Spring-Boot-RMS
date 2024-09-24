package com.abc.restaurant.services;

import org.springframework.data.jpa.repository.JpaRepository;

import com.abc.restaurant.models.AdminAddDinner;
import com.abc.restaurant.models.AdminAddDinnerDto;

                                              // Model name  // Type of the primary key
public interface AdminsAddDinnerRepository extends JpaRepository<AdminAddDinner, Integer> {

    public void save(AdminAddDinnerDto adminAddDinnerDto);
    
}
