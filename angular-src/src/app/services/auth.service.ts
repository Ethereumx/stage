import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { catchError, map } from 'rxjs/operators';
import { Observable, pipe } from 'rxjs';



@Injectable({
  providedIn: 'root'
})

export class AuthService {
    authToken: any;
    user: any;

  constructor(private http : HttpClient) {   }
    
    registerUser(user){
        let headers = new HttpHeaders();
        headers.append('Content-Type','application/json');
    return this.http.post('http://localhost:3000/users/register', user,{headers: headers})
      .pipe(map(res => res));
  }
    
    authenticateUser(user){
        let headers = new HttpHeaders();
        headers.append('Content-Type','application/json');
    return this.http.post('http://localhost:3000/users/authenticate', user,{headers: headers})
      .pipe(map(res => res));
    }
    
    getProfile(){        
        this.loadToken();
        const httpOptions = {
          headers: new HttpHeaders({
            'Content-Type':  'application/json',
            'Authorization': this.authToken
          })
        };
        /*headers.append('Access-Control-Allow-Origin', '*'); 
        headers.append('Access-Control-Allow-Headers', 'Authorization');         
        headers.append('Content-Type','application/json');
        headers.append('Authorization',this.authToken);*/
        return this.http.get('http://localhost:3000/users/profile',/*{headers: headers}*/ httpOptions)
            .pipe(map((res:any) => res ));
    }
    
    
    
    
    
    
    storeUserData(token,user){
        localStorage.setItem('id_token', token);
        localStorage.setItem('user' , JSON.stringify(user));
        this.authToken = token;
        this.user = user;
        
    }
    
    loadToken(){
        const token = localStorage.getItem('id_token');
        this.authToken = token;
        //console.log(token);
    }
    
    loggedIn() {
    return this.authToken;
    }
    
    logout(){
        this.authToken = null;
        this.user = null;
        localStorage.clear();
    }
}
