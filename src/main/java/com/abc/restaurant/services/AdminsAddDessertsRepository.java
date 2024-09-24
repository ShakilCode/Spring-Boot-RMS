package com.abc.restaurant.services;

import org.springframework.data.jpa.repository.JpaRepository;

import com.abc.restaurant.models.AdminAddDesserts;
import com.abc.restaurant.models.AdminAddDessertsDto;

                                              // Model name  // Type of the primary key
public interface AdminsAddDessertsRepository extends JpaRepository<AdminAddDesserts, Integer> {

    public void save(AdminAddDessertsDto adminAddDessertsDto);
    
}
