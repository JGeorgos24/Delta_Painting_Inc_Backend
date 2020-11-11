const express = require('express');
const router = express.Router();
const ctrl = require('../controllers');


router.get('/profile', ctrl.user.getProfile);
router.put('/profile', ctrl.user.editProfile);

module.exports = router;