import { Component, OnInit , ElementRef, Input } from '@angular/core';
import { HttpClient } from '@angular/common/http';

import { AuthService} from '../../services/auth.service';


@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
})
export class DashboardComponent implements OnInit {


  signature : any;
  selectedFile = null;
  signatureToVerify = '';
  FILE_TO_SIGNE_CHOOSED = false;
  FILE_TO_VERIFY_CHOOSED = false;
  Choose_file_to_sign = 'Choose file';
  Choose_file_to_verify = 'Choose file';
  VALID_SIGNATUR =null;


  constructor(
    private http: HttpClient,
    private authService : AuthService
  ) { }

  ngOnInit() {
    this.authService.loadToken();
  }


  onFileChange(event){
    this.selectedFile =  event.target.files[0];
    if(event.originalTarget.attributes.name.value == "FileToSign"){
      this.FILE_TO_SIGNE_CHOOSED  = true;
      this.FILE_TO_VERIFY_CHOOSED = false;
      this.Choose_file_to_sign = this.selectedFile.name;
      this.Choose_file_to_verify = 'Choose file';
    }
    if(event.originalTarget.attributes.name.value == "FileToVerify"){
      this.FILE_TO_SIGNE_CHOOSED  = false;
      this.FILE_TO_VERIFY_CHOOSED = true;
      this.Choose_file_to_verify = this.selectedFile.name;
      this.Choose_file_to_sign = 'Choose file';
    }
    // console.log(event.originalTarget.attributes.name.value);


  }

  signFile(){
    const fd = new FormData();
    fd.append('file', this.selectedFile, this.selectedFile.name);
    fd.append('data','ayoubbahmad');
    this.http.post('http://localhost:3000/api/sign',fd).subscribe((res:any)=>{
      if(res.success){
        this.signature = res.signature;
        //alert(this.signature);
      }
      console.log(res);
    });
  }

  veifyFile(){

    const fd = new FormData();
    fd.append('file', this.selectedFile, this.selectedFile.name);
    fd.append('signature',this.signatureToVerify);
    this.http.post('http://localhost:3000/api/verify',fd).subscribe((res:any)=>{
      if(res.success){
        this.VALID_SIGNATUR = res.verification;
      }
      //console.log(res);
    });
  }
}
