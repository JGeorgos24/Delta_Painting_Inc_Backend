const User = require('../models').User;
const City = require('../models').City;
const Post = require('../models').Post;

const constants = require('../constants');

const getProfile = (req, res) => {
    let sort = 'DESC';
    if(req.query.sorted === 'asc')
        sort = 'ASC';
    
    User.findByPk(req.user.id, {
        include: [
        //     {
        //         model: City,
        //         attributes: ['id', 'name', 'state', 'img', 'country']
        //     },
        //     {
        //         model: Post,
        //         attributes: ['id', 'title', 'img']
        //     }
        // ],
        // attributes: ['id', 'name', 'username', 'img', 'createdAt', 'email'],
        // order: [
        //     [{model: Post}, 'createdAt', sort]
        ]
    })
    .then(userProfile => {
        res.status(constants.SUCCESS).json(userProfile)
    })
    .catch(err => {
        res.status(constants.INTERNAL_SERVER_ERROR).send(`ERROR: ${err}`);
    })
}

const editProfile = (req, res) => {
    User.update(req.body, {
        where: {
            id: req.user.id
        },
        returning: true
    })
    .then(() => {
        User.findByPk(req.user.id, {
            include: [
                // {
                //     model: City,
                //     attributes: ['id', 'name', 'state', 'img', 'country']
                // }
            ],
            attributes: ['id', 'name', 'username', 'img', 'createdAt', 'email']
        })
        .then(userProfile => {
            res.status(constants.SUCCESS).json(userProfile)
        })
    })
    .catch(err => {
        res.status(constants.INTERNAL_SERVER_ERROR).send(`ERROR: ${err}`);
    })
}

module.exports = {
    getProfile,
    editProfile
}