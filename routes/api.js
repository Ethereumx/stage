const express = require('express');
const router = express.Router();

const fs = require('fs');
const jwa = require('jwa');
const sha1File = require('sha1-file');
const path = require('path');
const EthCrypto = require('eth-crypto');


//const fs = require('fs')

const EthUtil=require('ethereumjs-util')
const crypto = require('crypto')
 


//require multer for the file uploads
const multer = require('multer');
// // set the directory for the uploads to the uploaded to
var DIR = './uploads/';

//multer configs
let storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, DIR);
    },
    filename: (req, file, cb) => {
      cb(null, file.originalname);
    }
});


//define the type of upload multer would be doing and pass in its destination, in our case, its a single file with the name photo
var upload = multer({ storage: storage });

//upload.single('file') where file is input name in form
router.post('/sign', upload.single('file'),(req,res)=>{
  if (!req.file) {
      console.log("No file received");
      return res.send({
        success: false
      });

    } else {
      console.log('file received');
	const file = fs.readFileSync(req.file.path)
	  const keccak256hash = EthUtil.keccak256(file);
          const messageHash = keccak256hash.toString('hex');
 
	  const privateKey='1304a6035d0522d1d007a00b93e45afd714a21d3b63a475a16e4b896e185ac7d'

//possibility 1        
	const signature1 = EthCrypto.sign(
      		privateKey, // privateKey
      		messageHash // hash of message
  	);

	console.log("signature1",signature1)


//possibiliy 2
        const ecSignature = EthUtil.ecsign(keccak256hash, new Buffer(privateKey, 'hex') )
	console.log("signature 2", ecSignature)


    let v = EthUtil.bufferToHex(ecSignature.v);
    let r = EthUtil.bufferToHex(ecSignature.r);
    let s = EthUtil.bufferToHex(ecSignature.s);
console.log("v ",v,ecSignature.v)
console.log("r ",r)
console.log("s ",s)
// the same as posibility 1
	const aggregatedSignature= r+s.substring(2)+v.substring(2);
	console.log("signature rvc",aggregatedSignature)

 
//retriving public key from ecSignature
	let z= EthUtil.bufferToHex(EthUtil.ecrecover(keccak256hash, ecSignature.v, ecSignature.r, ecSignature.s)); 
	console.log("equivalent public key",z)

          //delete file
          fs.unlink(req.file.path, (err) => {
            if (err) throw err;
            console.log(req.file.filename+' was deleted');
          });

 
     return res.send({
            success: true,
            signature : aggregatedSignature
          });
 }
      //return result to frontEnd
          

});






router.post('/verify', upload.single('file'),(req,res)=>{
  if (!req.file) {
      console.log("No file received");
      return res.send({
        success: false
      });

    } else {
      console.log('file received');
      console.log("received signature",req.body.signature);
      const providedSignature=req.body.signature;
      //sign the file
      console.log('file received');
	const file = fs.readFileSync(req.file.path)

	  const keccak256hash = EthUtil.keccak256(file);
          const messageHash = keccak256hash.toString('hex');
console.log("verif messageHash",messageHash)
//0x b7063744e48162d477920a5ece381c1d26fdc57350ec99f95aabbd2b0b5760ad (64)   1695a04b5a4618d28b77028373f73e9198b69dd8f37860c821468c44640f8c38 (64)   1b(2)
//r+s.substring(2)+v.substring(2)
const r1=providedSignature.substring(2, 66);
const s1=providedSignature.substring(66, 130);
const v1=providedSignature.substring(130, 132);
console.log("Ecsignature variables",v1,r1,s1)


const publicHexKey='0xd2cf540fbd3f096ffcfe5de726cf87284b0d585fc0552bd6bb1a16b30cd84d103a0ce415d4bb4317a65fd7319b8a130227b6523d4691069d4f273a915a5360a5'
const publicKey=Buffer.from(publicHexKey, "hex")

const r=Buffer.from(r1, "hex") //notice the removal of ox
const v=parseInt(v1, 16);
const s=Buffer.from(s1, "hex")

console.log(r)
console.log("vrs",v, r, s)

const isValidSig=EthUtil.isValidSignature(v, r, s,true)
console.log("is a valid signature",isValidSig)

var verification = false
	if(isValidSig)
	{
          const input = messageHash;
          const signature = req.body.signature;

	  //crecover(msgHash: Buffer, v: number, r: Buffer, s:buffer)
          	const pubKey = EthUtil.ecrecover(keccak256hash, v, r, s)
		console.log("recovered public key", EthUtil.bufferToHex(pubKey))


		console.log(publicHexKey)
		console.log(EthUtil.bufferToHex(pubKey))

		if(publicHexKey==EthUtil.bufferToHex(pubKey)){
			console.log("pub keys matche");
			verification = true;
			}

      
	}
    //delete file
          fs.unlink(req.file.path, (err) => {
            if (err) throw err;
            console.log(req.file.filename+' was deleted');
          });
          //console.log(ecdsa.verify(input, signature, publicKey));

          //return result to frontEnd
          return res.send({
            success: true,
            verification : verification
  
        });
      }
});






module.exports = router;
