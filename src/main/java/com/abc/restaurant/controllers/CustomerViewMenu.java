package com.abc.restaurant.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.abc.restaurant.models.AdminAdd;
import com.abc.restaurant.models.AdminAddDesserts;
import com.abc.restaurant.models.AdminAddDinner;
import com.abc.restaurant.models.AdminAddDrink;
import com.abc.restaurant.models.AdminAddGallery;
import com.abc.restaurant.models.AdminAddLunch;
import com.abc.restaurant.services.AdminsAddDessertsRepository;
import com.abc.restaurant.services.AdminsAddDinnerRepository;
import com.abc.restaurant.services.AdminsAddDrinkRepository;
import com.abc.restaurant.services.AdminsAddGalleryRepository;
import com.abc.restaurant.services.AdminsAddLunchRepository;
import com.abc.restaurant.services.AdminsAddRepository;


@Controller
@RequestMapping("/customerviewmenu")
public class CustomerViewMenu {

    @Autowired
    private AdminsAddDinnerRepository repoDinner;

    @Autowired
    private AdminsAddRepository repoBreakfast;

    @Autowired
    private AdminsAddDessertsRepository repoDesserts;

    @Autowired
    private AdminsAddDrinkRepository repoDrink;

    @Autowired
    private AdminsAddGalleryRepository repoGallery;

    @Autowired
    private AdminsAddLunchRepository repoLunch;





    @GetMapping({"customerviewdinnermenu"})
    public String customerViewDinner(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAddDinner> adminadddinner = repoDinner.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminadddinner", adminadddinner);
        return "customerviewmenu/customerviewdinnermenu";
    }


    @GetMapping({"/customerviewbreakfastmenu"})
    public String customerViewBF(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAdd> adminadd = repoBreakfast.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminadd", adminadd);
        return "customerviewmenu/customerviewbreakfastmenu";
    }


    @GetMapping({"customerviewdessertsmenu"})
    public String customerViewDesserts(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAddDesserts> adminadddesserts = repoDesserts.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminadddesserts", adminadddesserts);
        return "customerviewmenu/customerviewdessertsmenu";
    }


    @GetMapping({"customerviewdrinkmenu"})
    public String customerViewDrink(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAddDrink> adminadddrink = repoDrink.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminadddrink", adminadddrink);
        return "customerviewmenu/customerviewdrinkmenu";
    }


    @GetMapping({"customerviewgallery"})
    public String customerViewGallery(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAddGallery> adminaddgallery = repoGallery.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminaddgallery", adminaddgallery);
        return "customerviewmenu/customerviewgallery";
    }


    @GetMapping({"customerviewlunchmenu"})
    public String customerViewLunch(Model model){
                                               // This parameter makes desending order of adminadd 
        List<AdminAddLunch> adminaddlunch = repoLunch.findAll(Sort.by(Sort.Direction.DESC, "id"));
        model.addAttribute("adminaddlunch", adminaddlunch);
        return "customerviewmenu/customerviewlunchmenu";
    }
    
}
