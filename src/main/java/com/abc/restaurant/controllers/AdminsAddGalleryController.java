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

import com.abc.restaurant.models.AdminAddGallery;
import com.abc.restaurant.models.AdminAddGalleryDto;
import com.abc.restaurant.services.AdminsAddGalleryRepository;

import jakarta.validation.Valid;




@Controller
@RequestMapping("/adminaddgallery")
public class AdminsAddGalleryController {

    @GetMapping("/admin")
    public String adminAddPage(){
        return "adminadd/admin";
    } 

    @GetMapping("/googlemaps")
    public String adminGoogleMap(){
        return "adminadd/googlemaps";
    }

    @GetMapping("/viewfoodmenulunch")
    public String adminViewAddFoodMenuLunch(){
        return "adminaddlunch/viewfoodmenulunch";
    }

    @GetMapping("/viewaddfoodgallery")
    public String adminViewAddFoodGallery(){
        return "adminadd/viewaddfoodgallery";
    }

    @Autowired
    private AdminsAddGalleryRepository repo;

    @GetMapping({"", "/"})
    public String showAdminAddGalleryList(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAddGallery> adminaddgallery = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminaddgallery", adminaddgallery);
        return "adminaddgallery/viewaddfoodgallery";
    }

    @GetMapping({"customerviewgallery"})
    public String customerViewGallery(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAddGallery> adminaddgallery = repo.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminaddgallery", adminaddgallery);
        return "adminaddgallery/customerviewgallery";
    }

    // Create new product
    @GetMapping("/addfoodgallery")
    public String showCreatePage(Model model){
        AdminAddGalleryDto adminAddGalleryDto = new AdminAddGalleryDto();
        model.addAttribute("adminAddGalleryDto", adminAddGalleryDto);
        // In the adminadd folder there is a adminadd called addfoodgallery
        return "adminaddgallery/addfoodgallery";
    }

@PostMapping("/addfoodgallery")
public String addfoodgallery(
    @Valid @ModelAttribute AdminAddGalleryDto adminAddGalleryDto,
    BindingResult result) {

        // Image file validation
        if (adminAddGalleryDto.getImageFile().isEmpty()) {
            result.addError(new FieldError("adminAddGalleryDto", "imageFile",
             "The image file is required"));
        }

        if (result.hasErrors()){
            return "adminaddgallery/addfoodgallery";
        }

        // Save image file and view in the list
        MultipartFile image = adminAddGalleryDto.getImageFile();
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

        AdminAddGallery adminaddgallery = new AdminAddGallery();
        adminaddgallery.setCreatedAt(new java.sql.Date(createdAt.getTime()));  // Fixed line
        adminaddgallery.setImageFileName(storageFileName);

        // Save this data on the database
        repo.save(adminaddgallery);

    return "redirect:/adminaddgallery";
}

    // Update the adminaddgallery details
    @GetMapping("/edit")
    public String showEditPage(
        Model model,
        @RequestParam int id
    ) {

        try {

            AdminAddGallery adminaddgallery = repo.findById(id).get();
            model.addAttribute("adminaddgallery", adminaddgallery);

            AdminAddGalleryDto adminAddGalleryDto = new AdminAddGalleryDto();

            model.addAttribute("adminAddGalleryDto", adminAddGalleryDto);


        } catch(Exception ex) {
            System.out.println("Exception : " + ex.getMessage());
            return "redirect:/adminaddgallery";
        }

        return "adminaddgallery/editaddfoodgallery";

    }

    // Post request for update the product 
    @PostMapping("/edit")
    public String updateProduct(
        Model model,
        @RequestParam int id,
        @Valid @ModelAttribute AdminAddGalleryDto adminAddGalleryDto,
        BindingResult result
    ) {

        try {

            AdminAddGallery adminaddgallery = repo.findById(id).get();
            model.addAttribute("adminaddgallery", adminaddgallery);

            // Check do we have any errors or not
            if(result.hasErrors()) {
                return "adminaddgallery/editaddfoodgallery";
            }


            // Check we have the image file or not
            if (!adminAddGalleryDto.getImageFile().isEmpty()) {
                //Delete old image
                String uploadDir = "public/images/";
                Path oldImagePath = Paths.get(uploadDir + adminaddgallery.getImageFileName());

                try {
                    Files.delete(oldImagePath);
                } catch (IOException ex) {
                    System.out.println("Exception : " + ex.getMessage());
                }

                // Save new image file
                MultipartFile image = adminAddGalleryDto.getImageFile();
                Date createdAt = new Date();
                String storageFileName = createdAt.getTime() + "_" + image.getOriginalFilename();

                try (InputStream inputStream = image.getInputStream()) {
                    Files.copy(inputStream, Paths.get(uploadDir + storageFileName),
                    StandardCopyOption.REPLACE_EXISTING);
                }

                adminaddgallery.setImageFileName(storageFileName);
            }

            // Update the other details

            repo.save(adminaddgallery);


        } catch (IOException ex) {
            System.out.println("Exception : " + ex.getMessage());
        }


        return "redirect:/adminaddgallery";
    }


    // This controller for adminadd
    @GetMapping("/delete")
    public String deleteProduct(@RequestParam int id) {

        try {
            AdminAddGallery adminaddgallery = repo.findById(id).get();

            //Delete product image
            Path imagePath = Paths.get("public/images/" + adminaddgallery.getImageFileName());

            try {
                Files.delete(imagePath);
            } catch (IOException ex) {
                System.out.println("Exception: " + ex.getMessage());
            }

            //Delete the product
            repo.delete(adminaddgallery);
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
        }

        return "redirect:/adminaddgallery";
    }

}
