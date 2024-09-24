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

import com.abc.restaurant.models.CustomerTableReservation;
import com.abc.restaurant.models.CustomerTableReservationDto;
import com.abc.restaurant.services.CustomersTableReservationRepository;

import jakarta.validation.Valid;




@Controller
@RequestMapping("/customerinterface")
public class CustomersTableReservationController {

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


    @GetMapping("/adminaddlunch")
    public String adminAddLunchPage(){
        return "adminaddlunch/addfoodmenulunch";
    }
    

    @Autowired
    private CustomersTableReservationRepository repo;

    @GetMapping({"", "/"})
    public String showCustomersTableReservationRepositoryList(Model model){
                                               // This parameter makes desending order of adminadd 
        List<CustomerTableReservation> customertablereservation = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("customertablereservation", customertablereservation);
        return "customerinterface/viewtablereservation";
    }
    

    @GetMapping("/adminviewtablereservations")
    public String showAnotherPage(Model model){
        // Fetch the data you need for the new page
        List<CustomerTableReservation> customertablereservation = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
    
        // Add the data to the model
        model.addAttribute("customertablereservation", customertablereservation);
        
        // Return the name of the new HTML file (e.g., anotherpage.html)
        return "customerinterface/adminviewtablereservations";
}


    // Create new product
    @GetMapping("/reservation")
    public String showCreatePage(Model model){
        CustomerTableReservationDto customerTableReservationDto = new CustomerTableReservationDto();
        model.addAttribute("customerTableReservationDto", customerTableReservationDto);
        // In the customerTableReservationDto folder there is a customertablereservation called reservation
        return "customerinterface/reservation";
    }

    @PostMapping("/reservation")
    public String addReservation(
        @Valid @ModelAttribute CustomerTableReservationDto customerTableReservationDto,
        BindingResult result,
        Model model) {
    
        // Check if there are validation errors
        if (result.hasErrors()) {
            // Return to the form with the validation errors
            return "customerinterface/reservation";
        }
    
        // If no errors, proceed with saving the data
        CustomerTableReservation customerTableReservation = new CustomerTableReservation();
        customerTableReservation.setName(customerTableReservationDto.getName());
        customerTableReservation.setEmail(customerTableReservationDto.getEmail());
        customerTableReservation.setPhone(customerTableReservationDto.getPhone());
        customerTableReservation.setDate(customerTableReservationDto.getDate());
        customerTableReservation.setTime(customerTableReservationDto.getTime());
        customerTableReservation.setStatus(customerTableReservationDto.getStatus());
        customerTableReservation.setPerson(customerTableReservationDto.getPerson());
    
        repo.save(customerTableReservation);
    
        return "redirect:/customerinterface";
    }
    

    // customer update the details
    @GetMapping("/edit")
    public String showEditPage(
        Model model,
        @RequestParam int id
    ) {

        try {

            CustomerTableReservation customerTableReservation = repo.findById(id).get();
            model.addAttribute("customerTableReservation", customerTableReservation);

            CustomerTableReservationDto customerTableReservationDto = new CustomerTableReservationDto();
            customerTableReservationDto.setName(customerTableReservation.getName());
            customerTableReservationDto.setEmail(customerTableReservation.getEmail());
            customerTableReservationDto.setPhone(customerTableReservation.getPhone());
            customerTableReservationDto.setDate(customerTableReservation.getDate());
            customerTableReservationDto.setTime(customerTableReservation.getTime());
            customerTableReservationDto.setPerson(customerTableReservation.getPerson());

            model.addAttribute("customerTableReservationDto", customerTableReservationDto);


        } catch(Exception ex) {
            System.out.println("Exception : " + ex.getMessage());
            return "redirect:/customerinterface";
        }

        return "customerinterface/edittablereservation";

    }

    // Post request for update the product 
    @PostMapping("/edit")
    public String updateProduct(
        Model model,
        @RequestParam int id,
        @Valid @ModelAttribute CustomerTableReservationDto customerTableReservationDto,
        BindingResult result
    ) {

        CustomerTableReservation customerTableReservation = repo.findById(id).get();
        model.addAttribute("customerTableReservation", customerTableReservation);
        // Check do we have any errors or not
        if(result.hasErrors()) {
            return "customerinterface/edittablereservation";
        }
        // Update the other details
        customerTableReservation.setName(customerTableReservationDto.getName());
        customerTableReservation.setEmail(customerTableReservationDto.getEmail());
        customerTableReservation.setPhone(customerTableReservationDto.getPhone());
        customerTableReservation.setDate(customerTableReservationDto.getDate());
        customerTableReservation.setTime(customerTableReservationDto.getTime());
        customerTableReservation.setPerson(customerTableReservationDto.getPerson());
        repo.save(customerTableReservation);


        return "redirect:/customerinterface";
    }

    // Admin update the order stauts
        @GetMapping("/adminedittablereservations")
        public String showEditPageAdmin(
            Model model,
            @RequestParam int id
        ) {
    
            try {
    
                CustomerTableReservation customerTableReservation = repo.findById(id).get();
                model.addAttribute("customerTableReservation", customerTableReservation);
    
                CustomerTableReservationDto customerTableReservationDto = new CustomerTableReservationDto();
                customerTableReservationDto.setName(customerTableReservation.getName());
                customerTableReservationDto.setEmail(customerTableReservation.getEmail());
                customerTableReservationDto.setPhone(customerTableReservation.getPhone());
                customerTableReservationDto.setDate(customerTableReservation.getDate());
                customerTableReservationDto.setTime(customerTableReservation.getTime());
                customerTableReservation.setStatus(customerTableReservationDto.getStatus());
                customerTableReservationDto.setPerson(customerTableReservation.getPerson());
    
                model.addAttribute("customerTableReservationDto", customerTableReservationDto);
    
    
            } catch(Exception ex) {
                System.out.println("Exception : " + ex.getMessage());
                return "redirect:/customerinterface";
            }
    
            return "customerinterface/adminedittablereservations";
    
        }

    // Post request for update the product admin 
    @PostMapping("/adminedittablereservations")
    public String updateProductAdmin(
        Model model,
        @RequestParam int id,
        @Valid @ModelAttribute CustomerTableReservationDto customerTableReservationDto,
        BindingResult result
    ) {

        CustomerTableReservation customerTableReservation = repo.findById(id).get();
        model.addAttribute("customerTableReservation", customerTableReservation);
        // Check do we have any errors or not
        if(result.hasErrors()) {
            return "customerinterface/adminedittablereservations";
        }
        // Update the other details
        customerTableReservation.setName(customerTableReservationDto.getName());
        customerTableReservation.setEmail(customerTableReservationDto.getEmail());
        customerTableReservation.setPhone(customerTableReservationDto.getPhone());
        customerTableReservation.setDate(customerTableReservationDto.getDate());
        customerTableReservation.setTime(customerTableReservationDto.getTime());
        customerTableReservation.setStatus(customerTableReservationDto.getStatus());
        customerTableReservation.setPerson(customerTableReservationDto.getPerson());
        repo.save(customerTableReservation);


        return "redirect:/customerinterface/adminviewtablereservations";
    }



    // This controller for adminadd
    @GetMapping("/delete")
    public String deleteProduct(@RequestParam int id) {

        try {
            CustomerTableReservation customertablereservation = repo.findById(id).get();

            //Delete the product
            repo.delete(customertablereservation);
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
        }

        return "redirect:/customerinterface";
    }

}
