package com.abc.restaurant.services;

import org.springframework.data.jpa.repository.JpaRepository;

import com.abc.restaurant.models.AdminAdd;
import com.abc.restaurant.models.AdminAddDto;

                                              // Model name  // Type of the primary key
public interface AdminsAddRepository extends JpaRepository<AdminAdd, Integer> {

    public void save(AdminAddDto adminAddDto);
    
}
