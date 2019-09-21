// Package Imports
var mongodb = require('mongodb');
var ObjectID = mongodb.ObjectID;
var crypto = require('crypto');
var express = require('express');
var bodyParser = require('body-parser');

// PASSWORD UTILS
// CREATE FUNCTION TO RANDOM SALT
var genRandomString = function (length) {
    return crypto.randomBytes(Math.ceil(length/2))
        .toString('hex')
        .slice(0, length);
};

var sha512 = function(password, salt) {
    var hash = crypto.createHmac('sha512', salt);
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt: salt,
        passwordHash: value
    };
};

function saltHashPassword(userPassword) {
    var salt = genRandomString(16);
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}

function checkHashPassword(userPassword, salt) {
    var passwordData = sha512(userPassword, salt);
    return passwordData
}

// Create Express Service
var app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

// Create MongoDB Client
var MongoClient = mongodb.MongoClient;

// Connection URL
var url = 'mongodb://localhost:27017'; // 27017 is default port

MongoClient.connect(url, {useNewUrlParser: true}, function(err, client) {
    if (err) {
        console.log('Unable to connect to mongoDB server. Error', err);
    } else {

        // Register
        app.post('/register', (request, response, next) => {
            var post_data = request.body;

            var plaint_password = post_data.password;
            var hash_data = saltHashPassword(plaint_password);

            var password = hash_data.passwordHash; // Save password hash
            var salt = hash_data.salt; // Save salt

            var name = post_data.name;
            var id = post_data.id;

            var insertJson = {
                'id': id,
                'password': password,
                'salt': salt,
                'name': name
            };
            var db = client.db('triptrackr');

            // Check if email exists
            db.collection('triptrackr')
                .find({'id': id})
                .count(function (err, number) {
                    if (number != 0) {
                        response.json('ID already exists');
                        console.log('ID already exists');
                    } else {
                        // Insert Data
                        db.collection('triptrackr')
                            .insertOne(insertJson, function (error, res) {
                                response.json('Registration success');
                                console.log('Registration success');
                        });
                    }
            });
        });

        // Login
        app.post('/login', (request, response, next) => {
            var post_data = request.body;

            var id = post_data.id;
            var userPassword = post_data.password;

            var db = client.db('triptrackr');

            // Check if email exists
            db.collection('triptrackr')
                .find({'id': id})
                .count(function (err, number) {
                    if (number == 0) {
                        response.json('ID does not exist');
                        console.log('ID does not exist');
                    } else {
                        // Insert Data
                        db.collection('triptrackr')
                            .findOne({'id': id}, function (error, user) {
                                var salt = user.salt // Get salt from user
                                var hashedPassword = checkHashPassword(userPassword, salt).passwordHash; // Pash password with salt
                                var encryptedPassword = user.password; // Get password from user
                                if (hashedPassword == encryptedPassword) {
                                    response.json('Login successful');
                                    console.log('Login successful');
                                }
                                else {
                                    response.json('Incorrect Password');
                                    console.log('Incorrect Password');
                                }
                            });
                    }
            });
        });

        // Start Web Server
        app.listen(3000, () => {
            console.log('Connected to MongoDB Server, WebService running on port 3000');
        });
    }
});
