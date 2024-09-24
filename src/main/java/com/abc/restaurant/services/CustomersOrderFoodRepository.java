package com.abc.restaurant.services;

import org.springframework.data.jpa.repository.JpaRepository;

import com.abc.restaurant.models.CustomerOrderFood;
import com.abc.restaurant.models.CustomerOrderFoodDto;

                                              // Model name  // Type of the primary key
public interface CustomersOrderFoodRepository extends JpaRepository<CustomerOrderFood, Integer> {

    public void save(CustomerOrderFoodDto customerOrderFoodDto);
    
}
    