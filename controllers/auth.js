require('dotenv').config();

const User = require('../models').User;
const constants = require('../constants');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const signup = (req, res) => {
    bcrypt.genSalt(10, (err, salt) => {
        if(err){
            res.status(constants.INTERNAL_SERVER_ERROR).send(`ERROR: ${err}`);
        }
        bcrypt.hash(req.body.password, salt, (err, hashedPwd) => {
            if(err){
                res.status(constants.INTERNAL_SERVER_ERROR).send(`ERROR: ${err}`);
            }
            req.body.password = hashedPwd;

            User.create(req.body)
            .then(newUser => {
                const token = jwt.sign(
                    {
                        username: newUser.username,
                        id: newUser.id
                    },
                    process.env.JWT_SECRET,
                    {
                        expiresIn: "30 days"
                    }
                )

                res.status(constants.SUCCESS).json({
                    "token" : token,
                    "user": newUser
                });
            })
            .catch(err => {
                console.log(err)
                res.status(constants.BAD_REQUEST).send(`ERROR: ${err}`);
            })
        })
    })
}

const login = (req, res) => {
    User.findOne({
        where: {
            username: req.body.username
        }
    })
    .then(foundUser => {
        console.log("FOUND A USER")
        if(foundUser){
            bcrypt.compare(req.body.password, foundUser.password, (err, match) => {
                if(match){

                    const token = jwt.sign(
                        {
                            username: foundUser.username,
                            id: foundUser.id
                        },
                        process.env.JWT_SECRET,
                        {
                            expiresIn: "30 days"
                        }
                    )
                    res.status(constants.SUCCESS).json({
                        "token" : token,
                        "user": foundUser
                    });
                } else {
                    res.status(constants.BAD_REQUEST).json({"ERROR": "Incorrect Username/Password"});
                }
            })
        }
        else{
            console.log("WRONG USERNAME")
            res.status(constants.SUCCESS).json({ERROR: "Incorrect Username/Password"});
            res.status(constants.BAD_REQUEST).json({ERROR: "Incorrect Username/Password"});
            
            
        }
    })
    .catch(err => {
        console.log(err)
        res.status(constants.BAD_REQUEST).json({"ERROR": "Incorrect Username/Password"});
    })
}

const verifyUser = (req, res) => {
    User.findByPk(req.user.id, {
        attributes: ['id', 'username', 'updatedAt', 'email', 'name', 'img']
    })
    .then(foundUser => {
        res.status(constants.SUCCESS).json(foundUser);
    })
    .catch(err => {
        res.status(constants.BAD_REQUEST).json({"ERROR": "Incorrect Username/Password"});
    })
}

module.exports = {
    signup,
    login,
    verifyUser
}
