package com.abc.restaurant.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.abc.restaurant.models.CustomerMakePayment;
import com.abc.restaurant.models.CustomerMakePaymentDto;
import com.abc.restaurant.services.CustomersMakePaymentRepository;

import jakarta.validation.Valid;




@Controller
@RequestMapping("/customerpayment")
public class CustomerMakePaymentController {
    
    @GetMapping("/viewcustomermakepayment")
    public String adminViewAddFoodMenuLunch(){
        return "customerpayment/viewcustomermakepayment";
    }


    @Autowired
    private CustomersMakePaymentRepository repo;

    @GetMapping({"", "/"})
    public String showaymentAddList(Model model){
                                               // This parameter makes desending order of adminadd 
        List<CustomerMakePayment> customerpayment = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("customerpayment", customerpayment);
        return "customerpayment/viewcustomermakepayment";
    }


    // Create new product
    @GetMapping("/customermakepayment")
    public String showMakePaymentPage(Model model){
        CustomerMakePaymentDto customerMakePaymentDto = new CustomerMakePaymentDto();
        model.addAttribute("customerMakePaymentDto", customerMakePaymentDto);
        // In the customerpayment folder there is a customerpayment called customermakepayment
        return "customerpayment/customermakepayment";
    }

@PostMapping("/customermakepayment")
public String customermakepayment(
    @Valid @ModelAttribute CustomerMakePaymentDto customerMakePaymentDto,
    BindingResult result,
    Model model) {

         // Check if there are validation errors
         if (result.hasErrors()) {
            // Return to the form with the validation errors
            return "customerpayment/customermakepayment";
        }


        CustomerMakePayment customerMakePayment = new CustomerMakePayment();
        customerMakePayment.setName(customerMakePaymentDto.getName());  // Fixing a typo here
        customerMakePayment.setCardnumber(customerMakePaymentDto.getCardnumber());
        customerMakePayment.setExpdate(customerMakePaymentDto.getExpdate());
        customerMakePayment.setCvc(customerMakePaymentDto.getCvc());

        // Save this data on the database
        repo.save(customerMakePayment);

    return "redirect:/customerpayment";
}

    // This controller for adminadd
    @GetMapping("/delete")
    public String deleteProduct(@RequestParam int id) {

        try {
            CustomerMakePayment customerMakePayment = repo.findById(id).get();

            //Delete the product
            repo.delete(customerMakePayment);
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
        }

        return "redirect:/customerpayment";
    }
}