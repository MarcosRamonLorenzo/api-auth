'use strict';

// Imports.
const config = require('./config');
const express = require('express');
const logger = require('morgan');
const mongojs = require('mongojs');
const https = require('https');
const fs = require('fs');
const helmet = require('helmet');
const cors = require('cors');

const TokenHelper = require('./helpers/token.helper'); 


// Declaraciones.

const app = express();

const port = config.PORT;
const urlDB = config.DB;


// Configuración de Base de Datos (Base de datos: "SD")
var db = mongojs(urlDB);
const id = mongojs.ObjectID;

//Declaraciones.

var allowCrossTokenOrigin = (req, res, next) => {

    res.header("Access-Control-Allow-Origin", "*"); // Permiso a cualquier URL. Mejor acotar
    return next();
};

var allowCrossTokenMethods = (req, res, next) => {

    res.header("Access-Control-Allow-Methods", "*"); // Mejor acotar (GET,PUT,POST,DELETE)
    return next();
};

var allowCrossTokenHeaders = (req, res, next) => {

    res.header("Access-Control-Allow-Headers", "*"); // Mejor acotar
    return next();
};


// --- Middlewares ---

app.use(cors());
app.use(helmet());
app.use(allowCrossTokenOrigin);
app.use(allowCrossTokenMethods);
app.use(allowCrossTokenHeaders);

app.use(logger('dev'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

var auth = (req, res, next) => { // declaramos la función auth

    // recogemos el token de la cabecera “Authorization”
    const queToken = req.headers.authorization?.split(' ')[1];
    TokenHelper.decodificaToken( queToken ).then( 
        userID => {
            req.user = {
                token: queToken,
                id: userID
            }
            return next(); // Pasamos el testigo al controlador de la ruta
        },
        err => {
            res.status(401);
            res.json({ result: 'KO', msg: `No autorizado: ${err.msg}` });
        }
    );
};


// --- Rutas de la API ---
// --- Rutas USER ---


// 1. Obtenemos todos los usuarios registrados en el sistema.
app.get('/api/user', auth, (req, res, next) => {
    db.user.find((err, documentos) => {
        if (err) return next(err);
        res.json(documentos);
    });
});

// 2.Obtenemos el usuario indicado por el {id}.
app.get('/api/user/:id', auth, (req, res, next) => {
    db.user.findOne({ _id: id(req.params.id) }, (err, elemento) => {
        if (err) return next(err);
        res.json(elemento);
    });
});


// 3.Registramos un nuevo usuario con toda su información.
app.post('/api/user', auth, (req, res, next) => {
    const nuevoElemento = req.body;

    db.user.save(nuevoElemento, (err, result) => {
        if (err) return next(err);
        res.json(result);
    });
});

// 4. Modificamos el usuario {id}.
app.put('/api/user/:id', auth, (req, res, next) => {
    const userID = req.params.id;
    const elementoNuevo = req.body;

    db.user.update(
        { _id: id(userID) },
        { $set: elementoNuevo },
        { safe: true, multi: false },
        (err, resultado) => {
            if (err) return next(err);
            res.json(resultado);
        }
    );
});

// 5. Eliminamos el usuario {id}.
app.delete('/api/user/:id', auth, (req, res, next) => {
    const elementoId = req.params.id;

    db.user.remove({ _id: id(elementoId) }, (err, resultado) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        res.json(resultado);
    });
});





/*Rutas Auth*/

app.get('/api/auth', auth, (req, res, next) => {
    //ver solo email y nombre !!!!!!!!!!!!!!!!!!!!!!!!!!!!
    db.user.find((err, documentos) => {
        if (err) return next(err);
        res.json(documentos);
    });
})






// --- Inicio del Servidor ---
// Lanzamos el servicio mediante un canal seguro
https.createServer({

    cert: fs.readFileSync('./cert/cert.pem'),
    key: fs.readFileSync('./cert/key.pem')

}, app).listen(port, function () {
    console.log(`API AUTH ejecutándose en
 https://localhost:${port}/api/{user|auth}/{id}`);
});