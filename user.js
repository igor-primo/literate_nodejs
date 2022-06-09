const bcrypt = require('bcryptjs'); // To hash and compare passwords.
const jwt = require('jsonwebtoken'); // To sign and verify jwts
const utils_c = require('./utils');
const error = require('./error');
const db = require('./db'); // To provide connection to DB

const utils = new utils_c();

class user {
    constructor(){}
    async signup(req, res){
        req.on('data', async chunk => {
            try {
                const body = await JSON.parse(chunk.toString());
                const {name, email, password} = body;
                if(!(name && email && password))
                    throw new error('We need the name, the email and the password.', 300);
                if(!utils.string_in_bounds(name, 1, 20))
                    throw new error('Name need to contain at most 20 characters');
                if(!utils.string_in_bounds(email, 1, 20))
                    throw new error('Email need to contain at most 20 characters');
                if(!utils.string_in_bounds(password, 1, 20))
                    throw new error('Password need to contain at most 20 characters');
                if(!utils.valid_email(email))
                    throw new error('Email invalid.', 300); // We need to check email validity
                // We will store the hash, not the bare password.
                const hash = await bcrypt.hash(password, 10); 
                // Let's first check if this user is already registered. 
                // Emails are unique, so we will use it.
                const registered_q = `SELECT id FROM users WHERE email = $1`;
                const registered_v = [ email ];
                const registered_query = await db.query(registered_q, registered_v);
                if(!(registered_query.rows.length == 0))
                    throw new error('User already registered', 300);
                const q = `INSERT INTO users VALUES(DEFAULT, $1, $2, $3) RETURNING id`;
                const v = [ name, email, hash ];
                const { rows } = await db.query(q, v);
                const id = rows[0].id;
                // Now we need to provide a token to the user.
                const token = jwt.sign({id}, process.env.PRIVATE_KEY, {algorithm: 'RS256'});
                utils.respond(token, 201, res);
            } catch(e) {
                console.log(e.message); //DEBUG
                if(!(e instanceof error))
                    return utils.respond('Internal error', 500, res);
                return utils.respond(e.message, e.status, res);
            }
        });
        req.on('error', err => {
            utils.respond('Internal error', 500, res);
        });
    }
    async authenticate(req, res) {
        try {
            const auth = req.headers['authorization'];
            const token = auth ? auth.split('Bearer ')[1] : null; // We take the token from the Authorization header.
            if(!token)
                throw new error('I need a JWT to authenticate you.', 401);
            const valid = await jwt.verify(token, process.env.PUBLIC_KEY, {algorithms: ['RS256']});
            if(!valid)
                throw new error('Invalid token', 401);
            return valid.id; // Return id. Our functionalities are executed only if this id is returned.
        } catch(e) {
            if(!(e instanceof error))
                return utils.respond('Internal error', 500, res); // In case db fails
            return utils.respond(e.message, e.status, res);
        }
    }

    async get_token(req, res){
        try {
            const params = new URLSearchParams(req.url.split('?')[1]).entries(); // Password and email are passed by query parameters.
            let email = '';
            let password = '';
            for(const param of params){
                switch(param[0]){
                    case 'email':
                        email = param[1];
                        break;
                    case 'password':
                        password = param[1];
                        break;
                    default:
                        break;
                }
            }
            if(!(email.length > 0))
                throw new error('I need your email', 401);
            if(!(utils.valid_email(email)))
                throw new error('Email invalid.', 401);
            if(!(password.length > 0))
                throw new error('I need your password', 401);
            const q = `SELECT id, password FROM users WHERE email = $1;`;
            const v = [ email ];
            const { rows } = await db.query(q, v);
            if(rows.length == 0)
                throw new error('User not in the database or incorrect password.', 401);
            if(!bcrypt.compareSync(password, rows[0].password))
                throw new error('User not in the database or incorrect password.', 401);
            const id = rows[0].id;
            const token = jwt.sign({id}, process.env.PRIVATE_KEY, {algorithm: 'RS256'});
            utils.respond(token, 200, res);
        } catch(e) {
            if(!(e instanceof error))
                return utils.respond('Internal error', 500, res);
            return utils.respond(e.message, e.status, res);
        }
    }

    async verify_token(req, res){
        try {
            const auth = req.headers['authorization'];
            const token = auth ? auth.split('Bearer ')[1] : null; // We take the token from the Authorization header.
            if(!token){
                // If the token is not found in the authorization header, seek it in the query params
                const token_param = new URLSearchParams(req.url.split('?')[1]).entries();
                let token_p = '';
                for(const param of token_param){
                    console.log(param); //DEBUG
                    if(param[0] === 'token') token_p = param[1];
                }
                if(token_p.length == 0)
                    throw new error('I need a JWT to authenticate you.', 401);
                const valid_p = await jwt.verify(token_p, process.env.PUBLIC_KEY, {algorithms: ['RS256']});
                if(!valid_p)
                    throw new error('Invalid token', 401);
                return utils.respond('Token OK', 200, res);
            }
            const valid = await jwt.verify(token, process.env.PUBLIC_KEY, {algorithms: ['RS256']});
            if(!valid)
                throw new error('Invalid token', 401);
            utils.respond('Token OK', 200, res);
        } catch(e) {
            if(!(e instanceof error))
                return utils.respond('Internal error', 500, res);
            return utils.respond(e.message, e.status, res);
        }
    }

    async put(id, req, res){
        req.on('data', async chunk => {
            try {
                const body = await JSON.parse(chunk.toString());
                const { name, email, password } = body;
                console.log(body); //DEBUG
                if(!(name && email && password))
                    throw new error('We need the name, the email and the password.', 300);
                if(!utils.string_in_bounds(name, 1, 20))
                    throw new error('Name need to contain at most 20 characters');
                if(!utils.string_in_bounds(email, 1, 20))
                    throw new error('Email need to contain at most 20 characters');
                if(!utils.string_in_bounds(password, 1, 20))
                    throw new error('Password need to contain at most 20 characters');
                if(!utils.valid_email(email))
                    throw new error('Email invalid.', 300); // We need to check email validity
                // Check if user exists
                const { rows } = await db.query(`SELECT id FROM users WHERE id = $1;`, [ id ]);
                if(rows.length == 0)
                    throw new error('User not registered.', 401);
                const hash = await bcrypt.hash(password, 10);
                const q = `UPDATE users SET name = $1, email = $2, password = $3 WHERE  id = $4;`;   
                const v = [ name, email, hash, id ];
                await db.query(q, v);
                utils.respond('User modified with success', 200, res);
            } catch(e) {
                console.log(e.message); //DEBUG
                if(!(e instanceof error))
                    return utils.respond('Internal error', 500, res);
                return utils.respond(e.message, e.status, res);
            }
        });
        req.on('error', err => {
            return utils.respond('Internal error', 500, res);
        });
    }

    async delete_user(id, req, res){
        try {
            const { rows } = await db.query(`SELECT id FROM users WHERE id = $1;`, [ id ]);
            if(rows.length == 0)
                throw new error('User not registered.', 401);
            await db.query(`DELETE FROM users WHERE id = $1;`, [ id ]);
            utils.respond('User delete with success', 200, res);
        } catch(e) {
            if(!(e instanceof error))
                return utils.respond('Internal error', 500, res);
            return utils.respond('User delete with success', 200, res);
        }
    }

}

module.exports = user;

