import { Component, OnInit } from '@angular/core';


import { ValidateService} from '../../services/validate.service';

import { AuthService} from '../../services/auth.service';

import { FlashMessagesService } from 'angular2-flash-messages';

import { Router } from '@angular/router';



@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css']
})

export class ProfileComponent implements OnInit {

  user : any;
    
  constructor(
    private authService : AuthService, 
    private router : Router
    ) { }

  ngOnInit() {
      
      //this.user = JSON.parse(localStorage.getItem('user'));
      
      //console.log(this.user);
      
      this.authService.getProfile().subscribe( (data: any) => {
          /*console.log('here Im');
          console.log(data);
          */
          this.user = data.user;
          //console.log(data.user);
        },
        err => {
          console.log("err");
          return false;
      });
      
      /*this.authService.registerUser(user).subscribe((data :any ) => {
      if(data.success){
        this.flashMessage.show('You are now registered and can log in', {cssClass: 'alert-success', timeout: 3000});
        this.router.navigate(['/login']);
      } else {
        this.flashMessage.show('Something went wrong', {cssClass: 'alert-danger', timeout: 3000});
        this.router.navigate(['/register']);
      }
    });*/
  }    
}
