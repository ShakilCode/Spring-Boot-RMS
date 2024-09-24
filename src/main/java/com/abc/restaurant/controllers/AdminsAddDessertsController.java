package com.abc.restaurant.controllers;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.abc.restaurant.models.AdminAddDesserts;
import com.abc.restaurant.models.AdminAddDessertsDto;
import com.abc.restaurant.services.AdminsAddDessertsRepository;

import jakarta.validation.Valid;




@Controller
@RequestMapping("/adminadddesserts")
public class AdminsAddDessertsController {

    @GetMapping("/admin")
    public String adminAddPage(){
        return "adminadd/admin";
    } 
    
    @GetMapping("/adminaddlunch")
    public String adminAddLunchPage(){
        return "adminaddlunch/addfoodmenulunch";
    }

    @GetMapping("/googlemaps")
    public String adminGoogleMap(){
        return "adminadd/googlemaps";
    }

    @GetMapping("/viewaddfoodmenulunch")
    public String adminViewAddFoodMenuLunch(){
        return "adminaddlunch/viewaddfoodmenulunch";
    }

    @GetMapping("/viewaddfoodmenudinner")
    public String adminViewAddFoodMenuDinner(){
        return "adminadddinner/viewaddfoodmenudinner";
    }

    @GetMapping("/viewaddfoodmenudesserts")
    public String adminViewAddFoodMenuDesserts(){
        return "adminadddesserts/viewaddfoodmenudesserts";
    }

    @Autowired
    private AdminsAddDessertsRepository repo;

    @GetMapping({"", "/"})
    public String showAdminAddList(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAddDesserts> adminadddesserts = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminadddesserts", adminadddesserts);
        return "adminadddesserts/viewaddfoodmenudesserts";
    }




    // Create new product
    @GetMapping("/addfoodmenudesserts")
    public String showCreatePage(Model model){
        AdminAddDessertsDto adminAddDessertsDto = new AdminAddDessertsDto();
        model.addAttribute("adminAddDessertsDto", adminAddDessertsDto);
        // In the adminAddDessertsDto folder there is a adminadddesserts called addfoodmenudesserts
        return "adminadddesserts/addfoodmenudesserts";
    }

@PostMapping("/addfoodmenudesserts")
public String addfoodmenuDesserts(
    @Valid @ModelAttribute AdminAddDessertsDto adminAddDessertsDto,
    BindingResult result) {

        // Image file validation
        if (adminAddDessertsDto.getImageFile().isEmpty()) {
            result.addError(new FieldError("adminAddDessertsDto", "imageFile",
             "The image file is required"));
        }

        if (result.hasErrors()){
            return "adminadddesserts/addfoodmenudesserts";
        }

        // Save image file and view in the list
        MultipartFile image = adminAddDessertsDto.getImageFile();
        Date createdAt = new Date();
        String storageFileName = createdAt.getTime() + "_" + image.getOriginalFilename();

        try {
            String uploadDir = "public/images/";
            Path uploadPath = Paths.get(uploadDir);

            if (!Files.exists(uploadPath)){
                Files.createDirectories(uploadPath);
            }

            try (InputStream inputStream = image.getInputStream()) {
                Files.copy(inputStream, Paths.get(uploadDir + storageFileName),
                StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException ex) {
            System.out.println("Exception : " + ex.getMessage());
        }

        AdminAddDesserts adminAddDesserts = new AdminAddDesserts();
        adminAddDesserts.setName(adminAddDessertsDto.getName());  // Fixing a typo here
        adminAddDesserts.setCategory(adminAddDessertsDto.getCategory());
        adminAddDesserts.setPrice(adminAddDessertsDto.getPrice());
        adminAddDesserts.setDescription(adminAddDessertsDto.getDescription());
        adminAddDesserts.setCreatedAt(new java.sql.Date(createdAt.getTime()));  // Fixed line
        adminAddDesserts.setImageFileName(storageFileName);

        // Save this data on the database
        repo.save(adminAddDesserts);

    return "redirect:/adminadddesserts";
}

    // Update the adminAdd details
    @GetMapping("/edit")
    public String showEditPage(
        Model model,
        @RequestParam int id
    ) {

        try {

            AdminAddDesserts adminAddDesserts = repo.findById(id).get();
            model.addAttribute("adminAddDesserts", adminAddDesserts);

            AdminAddDessertsDto adminAddDessertsDto = new AdminAddDessertsDto();
            adminAddDessertsDto.setName(adminAddDesserts.getName());
            adminAddDessertsDto.setCategory(adminAddDesserts.getCategory());
            adminAddDessertsDto.setPrice(adminAddDesserts.getPrice());
            adminAddDessertsDto.setDescription(adminAddDesserts.getDescription());

            model.addAttribute("adminAddDessertsDto", adminAddDessertsDto);


        } catch(Exception ex) {
            System.out.println("Exception : " + ex.getMessage());
            return "redirect:/adminadddesserts";
        }

        return "adminadddesserts/editaddfoodmenudesserts";

    }

    // Post request for update the product 
    @PostMapping("/edit")
    public String updateProduct(
        Model model,
        @RequestParam int id,
        @Valid @ModelAttribute AdminAddDessertsDto adminAddDessertsDto,
        BindingResult result
    ) {

        try {

            AdminAddDesserts adminAddDesserts = repo.findById(id).get();
            model.addAttribute("adminAddDesserts", adminAddDesserts);

            // Check do we have any errors or not
            if(result.hasErrors()) {
                return "adminadddesserts/editaddfoodmenuDesserts";
            }


            // Check we have the image file or not
            if (!adminAddDessertsDto.getImageFile().isEmpty()) {
                //Delete old image
                String uploadDir = "public/images/";
                Path oldImagePath = Paths.get(uploadDir + adminAddDesserts.getImageFileName());

                try {
                    Files.delete(oldImagePath);
                } catch (IOException ex) {
                    System.out.println("Exception : " + ex.getMessage());
                }

                // Save new image file
                MultipartFile image = adminAddDessertsDto.getImageFile();
                Date createdAt = new Date();
                String storageFileName = createdAt.getTime() + "_" + image.getOriginalFilename();

                try (InputStream inputStream = image.getInputStream()) {
                    Files.copy(inputStream, Paths.get(uploadDir + storageFileName),
                    StandardCopyOption.REPLACE_EXISTING);
                }

                adminAddDesserts.setImageFileName(storageFileName);
            }

            // Update the other details
            adminAddDesserts.setName(adminAddDessertsDto.getName());
            adminAddDesserts.setCategory(adminAddDessertsDto.getCategory());
            adminAddDesserts.setPrice(adminAddDessertsDto.getPrice());
            adminAddDesserts.setDescription(adminAddDessertsDto.getDescription());

            repo.save(adminAddDesserts);


        } catch (IOException ex) {
            System.out.println("Exception : " + ex.getMessage());
        }


        return "redirect:/adminadddesserts";
    }


    // This controller for adminadd
    @GetMapping("/delete")
    public String deleteProduct(@RequestParam int id) {

        try {
            AdminAddDesserts adminadddesserts = repo.findById(id).get();

            //Delete product image
            Path imagePath = Paths.get("public/images/" + adminadddesserts.getImageFileName());

            try {
                Files.delete(imagePath);
            } catch (IOException ex) {
                System.out.println("Exception: " + ex.getMessage());
            }

            //Delete the product
            repo.delete(adminadddesserts);
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
        }

        return "redirect:/adminadddesserts";
    }

}
