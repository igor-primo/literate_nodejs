// Import http code
const http = require('http');
// Import utils code to access helper utilities
const utils_c = require('./utils');
// Import user code to access app functionalities
const user_c = require('./user');

// Create the objects
const utils = new utils_c();
const user = new user_c();

// This function will handle requests
async function handler(req, res){
    const url = req.url;
    const met = req.method;
    if(url === '/api/user' && met === 'POST'){  // Sign up
        await user.signup(req, res);
    } else if(url === '/api/user' && met === 'DELETE'){ // Delete credentials
        const id = await user.authenticate(req, res); // User needs to be autheticated first.
                                                      // That is, in possenssion of a JWT.
        if(id)
            await user.delete_user(id, req, res);
    } else if(url === '/api/user' && met === 'PUT'){ // Change credentials
        const id = await user.authenticate(req, res); // User needs to be autheticated first.
                                                      // That is, in possenssion of a JWT.
        if(id)
            await user.put(id, req, res);
    } else if(url.match(/\/api\/authenticate\?*/) && met === 'GET'){ // Get a token
        await user.get_token(req, res);
    } else if(url.match(/\/api\/verify_token\?*/) && met === 'GET'){ // Verify token
        await user.verify_token(req, res);
    } else
        utils.respond('Route not found', 404, res);
}

const PORT = process.env.PORT || 5000;
http.createServer(handler).listen(PORT);

