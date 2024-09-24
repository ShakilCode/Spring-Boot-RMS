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

import com.abc.restaurant.models.AdminAddLunch;
import com.abc.restaurant.models.AdminAddLunchDto;
import com.abc.restaurant.services.AdminsAddLunchRepository;

import jakarta.validation.Valid;




@Controller
@RequestMapping("/adminaddlunch")
public class AdminsAddLunchController {

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

    @Autowired
    private AdminsAddLunchRepository repo;

    @GetMapping({"", "/"})
    public String showAdminAddList(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAddLunch> adminaddlunch = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminaddlunch", adminaddlunch);
        return "adminaddlunch/viewaddfoodmenulunch";
    }


    // Create new product
    @GetMapping("/addfoodmenulunch")
    public String showCreatePage(Model model){
        AdminAddLunchDto adminAddLunchDto = new AdminAddLunchDto();
        model.addAttribute("adminAddLunchDto", adminAddLunchDto);
        // In the adminaddlunch folder there is a adminaddlunch called addfoodmenulunch
        return "adminaddlunch/addfoodmenulunch";
    }

@PostMapping("/addfoodmenulunch")
public String addfoodmenulunch(
    @Valid @ModelAttribute AdminAddLunchDto adminAddLunchDto,
    BindingResult result) {

        // Image file validation
        if (adminAddLunchDto.getImageFile().isEmpty()) {
            result.addError(new FieldError("adminAddLunchDto", "imageFile",
             "The image file is required"));
        }

        if (result.hasErrors()){
            return "adminaddlunch/addfoodmenulunch";
        }

        // Save image file and view in the list
        MultipartFile image = adminAddLunchDto.getImageFile();
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

        AdminAddLunch adminAddLunch = new AdminAddLunch();
        adminAddLunch.setName(adminAddLunchDto.getName());  // Fixing a typo here
        adminAddLunch.setCategory(adminAddLunchDto.getCategory());
        adminAddLunch.setPrice(adminAddLunchDto.getPrice());
        adminAddLunch.setDescription(adminAddLunchDto.getDescription());
        adminAddLunch.setCreatedAt(new java.sql.Date(createdAt.getTime()));  // Fixed line
        adminAddLunch.setImageFileName(storageFileName);

        // Save this data on the database
        repo.save(adminAddLunch);

    return "redirect:/adminaddlunch";
}

    // Update the adminAdd details
    @GetMapping("/edit")
    public String showEditPage(
        Model model,
        @RequestParam int id
    ) {

        try {

            AdminAddLunch adminAddLunch = repo.findById(id).get();
            model.addAttribute("adminAddLunch", adminAddLunch);

            AdminAddLunchDto adminAddLunchDto = new AdminAddLunchDto();
            adminAddLunchDto.setName(adminAddLunch.getName());
            adminAddLunchDto.setCategory(adminAddLunch.getCategory());
            adminAddLunchDto.setPrice(adminAddLunch.getPrice());
            adminAddLunchDto.setDescription(adminAddLunch.getDescription());

            model.addAttribute("adminAddLunchDto", adminAddLunchDto);


        } catch(Exception ex) {
            System.out.println("Exception : " + ex.getMessage());
            return "redirect:/adminaddlunch";
        }

        return "adminaddlunch/editaddfoodmenulunch";

    }

    // Post request for update the product 
    @PostMapping("/edit")
    public String updateProduct(
        Model model,
        @RequestParam int id,
        @Valid @ModelAttribute AdminAddLunchDto adminAddLunchDto,
        BindingResult result
    ) {

        try {

            AdminAddLunch adminAddLunch = repo.findById(id).get();
            model.addAttribute("adminAddLunch", adminAddLunch);

            // Check do we have any errors or not
            if(result.hasErrors()) {
                return "adminaddlunch/editaddfoodmenulunch";
            }


            // Check we have the image file or not
            if (!adminAddLunchDto.getImageFile().isEmpty()) {
                //Delete old image
                String uploadDir = "public/images/";
                Path oldImagePath = Paths.get(uploadDir + adminAddLunch.getImageFileName());

                try {
                    Files.delete(oldImagePath);
                } catch (IOException ex) {
                    System.out.println("Exception : " + ex.getMessage());
                }

                // Save new image file
                MultipartFile image = adminAddLunchDto.getImageFile();
                Date createdAt = new Date();
                String storageFileName = createdAt.getTime() + "_" + image.getOriginalFilename();

                try (InputStream inputStream = image.getInputStream()) {
                    Files.copy(inputStream, Paths.get(uploadDir + storageFileName),
                    StandardCopyOption.REPLACE_EXISTING);
                }

                adminAddLunch.setImageFileName(storageFileName);
            }

            // Update the other details
            adminAddLunch.setName(adminAddLunchDto.getName());
            adminAddLunch.setCategory(adminAddLunchDto.getCategory());
            adminAddLunch.setPrice(adminAddLunchDto.getPrice());
            adminAddLunch.setDescription(adminAddLunchDto.getDescription());

            repo.save(adminAddLunch);


        } catch (IOException ex) {
            System.out.println("Exception : " + ex.getMessage());
        }


        return "redirect:/adminaddlunch";
    }


    // This controller for adminadd
    @GetMapping("/delete")
    public String deleteLunchProduct(@RequestParam int id) {

        try {
            AdminAddLunch adminaddlunch = repo.findById(id).get();

            //Delete product image
            Path imagePath = Paths.get("public/images/" + adminaddlunch.getImageFileName());

            try {
                Files.delete(imagePath);
            } catch (IOException ex) {
                System.out.println("Exception: " + ex.getMessage());
            }

            //Delete the product
            repo.delete(adminaddlunch);
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
        }

        return "redirect:/adminaddlunch";
    }

}
