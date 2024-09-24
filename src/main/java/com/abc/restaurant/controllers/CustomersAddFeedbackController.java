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

import com.abc.restaurant.models.CustomerAddFeedback;
import com.abc.restaurant.models.CustomerAddFeedbackDto;
import com.abc.restaurant.services.CustomersAddFeedbackRepository;

import jakarta.validation.Valid;




@Controller
@RequestMapping("/customerfeedback")
public class CustomersAddFeedbackController {

    @GetMapping("/admin")
    public String adminAddPage(){
        return "adminadd/admin";
    } 

    @GetMapping("/about")
    public String about(){
        return "customerinterface/about";
    } 

    @GetMapping("/blog-single")
    public String blogSingle(){
        return "customerinterface/blog-single";
    } 

    @GetMapping("/viewtablereservation")
    public String viewtablereservation(){
        return "customerinterface/viewtablereservation";
    } 

    @GetMapping("/blog")
    public String blog(){
        return "customerinterface/blog";
    } 

    @GetMapping("/contact")
    public String contact(){
        return "customerinterface/contact";
    } 

    @GetMapping("/menu")
    public String menu(){
        return "customerinterface/menu";
    } 


    @GetMapping("/index")
    public String index(){
        return "customerinterface/index";
    } 
    

    @Autowired
    private CustomersAddFeedbackRepository repo;

    @GetMapping({"", "/"})
    public String showCustomersAddFeedbackRepositoryList(Model model){
                                               // This parameter makes desending order of adminadd 
        List<CustomerAddFeedback> customeraddfeedback = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("customeraddfeedback", customeraddfeedback);
        return "customerfeedback/customerviewfeedback";
        
    }

    @GetMapping("/adminviewfeedback")
    public String showAnotherPage(Model model){
        // Fetch the data you need for the new page
        List<CustomerAddFeedback> customeraddfeedback = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
    
        // Add the data to the model
        model.addAttribute("customeraddfeedback", customeraddfeedback);
        
        // Return the name of the new HTML file (e.g., anotherpage.html)
        return "customerfeedback/adminviewfeedback";
}


    // Create new product
    @GetMapping("/customeraddfeedback")
    public String showCustomerOrderForm(Model model){
        CustomerAddFeedbackDto customerAddFeedbackDto = new CustomerAddFeedbackDto();
        model.addAttribute("customerAddFeedbackDto", customerAddFeedbackDto);
        // In the customerAddFeedbackDto folder there is a customeraddfeedback called reservation
        return "customerfeedback/customeraddfeedback";
    }

    @PostMapping("/customeraddfeedback")
    public String addReservation(
        @Valid @ModelAttribute CustomerAddFeedbackDto customerAddFeedbackDto,
        BindingResult result,
        Model model) {
    
        // Check if there are validation errors
        if (result.hasErrors()) {
            // Return to the form with the validation errors
            return "customerfeedback/customeraddfeedback";
        }
    
        // If no errors, proceed with saving the data
        CustomerAddFeedback customerAddFeedback = new CustomerAddFeedback();
        customerAddFeedback.setRate(customerAddFeedbackDto.getRate());
        customerAddFeedback.setDescription(customerAddFeedbackDto.getDescription());
    
        repo.save(customerAddFeedback);
    
        return "redirect:/customerfeedback";
    }
    

    // customer update the details
    @GetMapping("/edit")
    public String showEditPage(
        Model model,
        @RequestParam int id
    ) {

        try {

            CustomerAddFeedback customerAddFeedback = repo.findById(id).get();
            model.addAttribute("customerAddFeedback", customerAddFeedback);

            CustomerAddFeedbackDto customerAddFeedbackDto = new CustomerAddFeedbackDto();
            customerAddFeedbackDto.setRate(customerAddFeedback.getRate());
            customerAddFeedbackDto.setDescription(customerAddFeedback.getDescription());

            model.addAttribute("customerAddFeedbackDto", customerAddFeedbackDto);


        } catch(Exception ex) {
            System.out.println("Exception : " + ex.getMessage());
            return "redirect:/customerfeedback";
        }

        return "customerfeedback/customereditfeedback";

    }

    // Post request for update the product 
    @PostMapping("/edit")
    public String updateProduct(
        Model model,
        @RequestParam int id,
        @Valid @ModelAttribute CustomerAddFeedbackDto customerAddFeedbackDto,
        BindingResult result
    ) {

        CustomerAddFeedback customerAddFeedback = repo.findById(id).get();
        model.addAttribute("customerAddFeedback", customerAddFeedback);
        // Check do we have any errors or not
        if(result.hasErrors()) {
            return "customerfeedback/customereditfeedback";
        }
        // Update the other details
        customerAddFeedback.setRate(customerAddFeedbackDto.getRate());
        customerAddFeedback.setDescription(customerAddFeedbackDto.getDescription());
        repo.save(customerAddFeedback);


        return "redirect:/customerfeedback";
    }


    // This controller for adminadd
    @GetMapping("/delete")
    public String deleteProduct(@RequestParam int id) {

        try {
            CustomerAddFeedback customeraddfeedback = repo.findById(id).get();

            //Delete the product
            repo.delete(customeraddfeedback);
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
        }

        return "redirect:/customerfeedback";
    }

    @GetMapping("/adminDelete")
    public String adminDeleteProduct(@RequestParam int id) {

        try {
            CustomerAddFeedback customeraddfeedback = repo.findById(id).get();

            //Delete the product
            repo.delete(customeraddfeedback);
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
        }

        return "redirect:/customerfeedback/adminvieworderfood";
    }

}
