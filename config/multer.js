import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import {dirname} from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname,'..', './uploads/product');
   
    fs.mkdirSync(uploadDir,{ recursive: true});
    cb(null, uploadDir);
},
filename:function(req,file,cb){
    cb(null,file.filename + '_' + Date.now() + '_' + file.originalname);
}
   
});

const upload = multer({ storage: storage });

export default upload;