class util {
    constructor(){

        this.EMAIL_REG = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

    }
    respond(message, status, res){
        // We write the status code and the content type into the response headers
        // We use application/json to simplify our lives
        res.writeHead(status, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({msg: message}));
    }
    valid_email(email){
        return email.match(this.EMAIL_REG);
    }
    string_in_bounds(str, min, max){
        return min <= str.length && str.length <= max;
    }
}

module.exports = util;

