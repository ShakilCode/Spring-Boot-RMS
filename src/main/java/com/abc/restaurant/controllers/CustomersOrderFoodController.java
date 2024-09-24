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

import com.abc.restaurant.models.CustomerOrderFood;
import com.abc.restaurant.models.CustomerOrderFoodDto;
import com.abc.restaurant.services.CustomersOrderFoodRepository;

import jakarta.validation.Valid;




@Controller
@RequestMapping("/customerinterfaceorderfood")
public class CustomersOrderFoodController {

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
    private CustomersOrderFoodRepository repo;

    @GetMapping({"", "/"})
    public String showCustomersOrderFoodRepositoryList(Model model){
                                               // This parameter makes desending order of adminadd 
        List<CustomerOrderFood> customerorderfood = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("customerorderfood", customerorderfood);
        return "customerinterfaceorderfood/vieworderfood";
        
    }

    @GetMapping("/adminvieworderfood")
    public String showAnotherPage(Model model){
        // Fetch the data you need for the new page
        List<CustomerOrderFood> customerorderfood = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
    
        // Add the data to the model
        model.addAttribute("customerorderfood", customerorderfood);
        
        // Return the name of the new HTML file (e.g., anotherpage.html)
        return "customerinterfaceorderfood/adminvieworderfood";
}


    // Create new product
    @GetMapping("/customerorderfood")
    public String showCustomerOrderForm(Model model){
        CustomerOrderFoodDto customerOrderFoodDto = new CustomerOrderFoodDto();
        model.addAttribute("customerOrderFoodDto", customerOrderFoodDto);
        // In the customerOrderFoodDto folder there is a customerorderfood called reservation
        return "customerinterfaceorderfood/customerorderfood";
    }

    @PostMapping("/customerorderfood")
    public String addReservation(
        @Valid @ModelAttribute CustomerOrderFoodDto customerOrderFoodDto,
        BindingResult result,
        Model model) {
    
        // Check if there are validation errors
        if (result.hasErrors()) {
            // Return to the form with the validation errors
            return "customerinterfaceorderfood/customerorderfood";
        }
    
        // If no errors, proceed with saving the data
        CustomerOrderFood customerOrderFood = new CustomerOrderFood();
        customerOrderFood.setName(customerOrderFoodDto.getName());
        customerOrderFood.setType(customerOrderFoodDto.getType());
        customerOrderFood.setPlace(customerOrderFoodDto.getPlace());
        customerOrderFood.setPhone(customerOrderFoodDto.getPhone());
        customerOrderFood.setDescription(customerOrderFoodDto.getDescription());
        customerOrderFood.setTime(customerOrderFoodDto.getTime());
        customerOrderFood.setStatus(customerOrderFoodDto.getStatus());
    
        repo.save(customerOrderFood);
    
        return "redirect:/customerinterfaceorderfood";
    }
    

    // customer update the details
    @GetMapping("/edit")
    public String showEditPage(
        Model model,
        @RequestParam int id
    ) {

        try {

            CustomerOrderFood customerOrderFood = repo.findById(id).get();
            model.addAttribute("customerOrderFood", customerOrderFood);

            CustomerOrderFoodDto customerOrderFoodDto = new CustomerOrderFoodDto();
            customerOrderFoodDto.setName(customerOrderFood.getName());
            customerOrderFoodDto.setType(customerOrderFood.getType());
            customerOrderFoodDto.setPlace(customerOrderFood.getPlace());
            customerOrderFoodDto.setPhone(customerOrderFood.getPhone());
            customerOrderFoodDto.setDescription(customerOrderFood.getDescription());
            customerOrderFoodDto.setTime(customerOrderFood.getTime());

            model.addAttribute("customerOrderFoodDto", customerOrderFoodDto);


        } catch(Exception ex) {
            System.out.println("Exception : " + ex.getMessage());
            return "redirect:/customerinterfaceorderfood";
        }

        return "customerinterfaceorderfood/editorderfood";

    }

    // Post request for update the product 
    @PostMapping("/edit")
    public String updateProduct(
        Model model,
        @RequestParam int id,
        @Valid @ModelAttribute CustomerOrderFoodDto customerOrderFoodDto,
        BindingResult result
    ) {

        CustomerOrderFood customerOrderFood = repo.findById(id).get();
        model.addAttribute("customerOrderFood", customerOrderFood);
        // Check do we have any errors or not
        if(result.hasErrors()) {
            return "customerinterfaceorderfood/editorderfood";
        }
        // Update the other details
        customerOrderFood.setName(customerOrderFoodDto.getName());
        customerOrderFood.setType(customerOrderFoodDto.getType());
        customerOrderFood.setPlace(customerOrderFoodDto.getPlace());
        customerOrderFood.setPhone(customerOrderFoodDto.getPhone());
        customerOrderFood.setDescription(customerOrderFoodDto.getDescription());
        customerOrderFood.setTime(customerOrderFoodDto.getTime());
        repo.save(customerOrderFood);


        return "redirect:/customerinterfaceorderfood";
    }

    // Admin update the order stauts
        @GetMapping("/admineditorderfood")
        public String showEditPageAdmin(
            Model model,
            @RequestParam int id
        ) {
    
            try {
    
                CustomerOrderFood customerOrderFood = repo.findById(id).get();
                model.addAttribute("customerOrderFood", customerOrderFood);
    
                CustomerOrderFoodDto customerOrderFoodDto = new CustomerOrderFoodDto();
                customerOrderFoodDto.setName(customerOrderFood.getName());
                customerOrderFoodDto.setType(customerOrderFood.getType());
                customerOrderFoodDto.setPlace(customerOrderFood.getPlace());
                customerOrderFoodDto.setPhone(customerOrderFood.getPhone());
                customerOrderFoodDto.setDescription(customerOrderFood.getDescription());
                customerOrderFoodDto.setTime(customerOrderFood.getTime());
                customerOrderFoodDto.setStatus(customerOrderFood.getStatus());
    
                model.addAttribute("customerOrderFoodDto", customerOrderFoodDto);
    
    
            } catch(Exception ex) {
                System.out.println("Exception : " + ex.getMessage());
                return "redirect:/customerinterfaceorderfood";
            }
    
            return "customerinterfaceorderfood/admineditorderfood";
    
        }

    // Post request for update the product admin 
    @PostMapping("/admineditorderfood")
    public String updateProductAdmin(
        Model model,
        @RequestParam int id,
        @Valid @ModelAttribute CustomerOrderFoodDto customerOrderFoodDto,
        BindingResult result
    ) {

        CustomerOrderFood customerOrderFood = repo.findById(id).get();
        model.addAttribute("customerOrderFood", customerOrderFood);
        // Check do we have any errors or not
        if(result.hasErrors()) {
            return "customerinterfaceorderfood/admineditorderfood";
        }
        // Update the other details
        customerOrderFood.setName(customerOrderFoodDto.getName());
        customerOrderFood.setType(customerOrderFoodDto.getType());
        customerOrderFood.setPlace(customerOrderFoodDto.getPlace());
        customerOrderFood.setPhone(customerOrderFoodDto.getPhone());
        customerOrderFood.setDescription(customerOrderFoodDto.getDescription());
        customerOrderFood.setTime(customerOrderFoodDto.getTime());
        customerOrderFood.setStatus(customerOrderFoodDto.getStatus());
        repo.save(customerOrderFood);


        return "redirect:/customerinterfaceorderfood/adminvieworderfood";
    }



    // This controller for adminadd
    @GetMapping("/delete")
    public String deleteProduct(@RequestParam int id) {

        try {
            CustomerOrderFood customerorderfood = repo.findById(id).get();

            //Delete the product
            repo.delete(customerorderfood);
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
        }

        return "redirect:/customerinterfaceorderfood";
    }

    @GetMapping("/adminDelete")
    public String adminDeleteProduct(@RequestParam int id) {

        try {
            CustomerOrderFood customerorderfood = repo.findById(id).get();

            //Delete the product
            repo.delete(customerorderfood);
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
        }

        return "redirect:/customerinterfaceorderfood/adminvieworderfood";
    }

}
