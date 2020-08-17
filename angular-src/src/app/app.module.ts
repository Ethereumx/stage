import { BrowserModule } from '@angular/platform-browser';
import { NgModule,enableProdMode } from '@angular/core';
import {RouterModule, Routes} from '@angular/router';

import { AppComponent } from './app.component';
import { NavbarComponent } from './components/navbar/navbar.component';
import { LoginComponent } from './components/login/login.component';
import { RegisterComponent } from './components/register/register.component';
import { HomeComponent } from './components/home/home.component';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { ProfileComponent } from './components/profile/profile.component';

import { FormsModule, ReactiveFormsModule } from '@angular/forms';


import { ValidateService } from './services/validate.service';

import { AuthService } from './services/auth.service';

import {AuthGuard} from './guards/auth.guard';
import {UnAuthGuard} from './guards/unauth.guard';

import { FlashMessagesModule } from 'angular2-flash-messages';

import { HttpClientModule } from '@angular/common/http';


enableProdMode();

const appRoutes: Routes =  [
  {path:'', component: HomeComponent},
  {path:'register', component: RegisterComponent,canActivate:[UnAuthGuard]},
  {path:'login', component: LoginComponent,canActivate:[UnAuthGuard]},
  {path:'dashboard', component: DashboardComponent,canActivate:[AuthGuard]},
  {path:'profile', component: ProfileComponent ,canActivate:[AuthGuard]}
]

@NgModule({
  declarations: [
    AppComponent,
    NavbarComponent,
    LoginComponent,
    RegisterComponent,
    HomeComponent,
    DashboardComponent,

    ProfileComponent
  ],
  imports: [
    RouterModule.forRoot(appRoutes),
    BrowserModule,
    FormsModule,
    HttpClientModule,
    FlashMessagesModule.forRoot(),

  ],
  providers: [ValidateService, AuthService,AuthGuard,UnAuthGuard],
  bootstrap: [AppComponent]
})
export class AppModule { }
