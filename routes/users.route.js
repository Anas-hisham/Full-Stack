const express = require('express');

const router = express.Router();

const multer = require('multer');

const diskStorage = multer.diskStorage({

    // destination => To Upload File
    destinatiofn: function (req, file, cb) {
        cb(null, 'uploads');
    },

    // filename => To Change FileName Before Upload To Make It Uniqe
    filename: function (req, file, cb) {

        // Like image/png It Will Take png 
        const ext = file.mimetype.split('/')[1];
        const fileName = `user-${Date.now()}.${ext}`;
        cb(null, fileName);
    }
})

// To Upload Images Only Not PDF
const fileFilter = (req, file, cb) => {
    const imageType = file.mimetype.split('/')[0];

    if (imageType === 'image') {
        return cb(null, true)
    } else {
        return cb(appError.create('file must be an image', 400), false)
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
