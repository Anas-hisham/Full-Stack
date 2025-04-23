const express = require('express');

const router = express.Router();

const multer = require('multer');

const diskStorage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, 'uploads'); // store files in 'uploads' folder
    },
    filename: function (req, file, cb) {
      const ext = file.mimetype.split('/')[1]; // png, jpg, jpeg
      const fileName = `user-${Date.now()}.${ext}`;
      cb(null, fileName); // generate unique name like: user-1713644091513.jpg
    }
  })
  

// To Upload Images Only Not PDF
const fileFilter = (req, file, cb) => {
    const imageType = file.mimetype.split('/')[0]; // image/png → image
    if (imageType === 'image') {
      cb(null, true); // accept file
    } else {
      cb(appError.create('file must be an image', 400), false); // reject file
    }
  }
  

const upload = multer({ storage: diskStorage, fileFilter })


const usersController = require('../controllers/users.controller')
const verifyToken = require('../middleware/verfiyToken');
const appError = require('../utils/appError');
// get all users

// register

// login

router.route('/')
    .get(verifyToken, usersController.getAllUsers)

router.route('/register')
    .post(upload.single('avatar'), usersController.register)

router.route('/login')
    .post(usersController.login)

module.exports = router;
