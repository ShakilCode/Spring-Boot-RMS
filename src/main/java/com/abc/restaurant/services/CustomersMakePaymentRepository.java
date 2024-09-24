package com.abc.restaurant.services;

import org.springframework.data.jpa.repository.JpaRepository;

import com.abc.restaurant.models.CustomerMakePayment;
import com.abc.restaurant.models.CustomerMakePaymentDto;

                                              // Model name  // Type of the primary key
public interface CustomersMakePaymentRepository extends JpaRepository<CustomerMakePayment, Integer> {

    public void save(CustomerMakePaymentDto customerMakePaymentDto);
    
}
